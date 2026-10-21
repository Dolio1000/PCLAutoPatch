// PCLAutoPatch - metadata-aware auto patcher for PCL 2.99 download/modpack gates.
// C++17, no external dependencies.
//
// It locates PCL.PageDownloadInstall.LoaderInit and
// PCL.ModModpack.ModpackInstall(String,String,String) by metadata name and
// method-body shape, reconstructs the missing IL using the new assembly's
// tokens, relocates the larger ModpackInstall body into the last PE section,
// and writes a separate patched copy. The input file is never modified.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

using Bytes = std::vector<uint8_t>;

static void fail(const std::string& msg) { throw std::runtime_error(msg); }

static std::string hx(uint32_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%X", v);
    return std::string(buf);
}

static std::string hx8(uint32_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%08X", v);
    return std::string(buf);
}

static uint16_t rd16(const Bytes& b, size_t o) {
    if (o + 2 > b.size()) fail("read16 out of bounds at " + hx((uint32_t)o));
    return (uint16_t)(b[o] | ((uint16_t)b[o + 1] << 8));
}

static uint32_t rd32(const Bytes& b, size_t o) {
    if (o + 4 > b.size()) fail("read32 out of bounds at " + hx((uint32_t)o));
    return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) |
           ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}

static int32_t rdi32(const Bytes& b, size_t o) {
    return (int32_t)rd32(b, o);
}

static uint64_t rd64(const Bytes& b, size_t o) {
    if (o + 8 > b.size()) fail("read64 out of bounds at " + hx((uint32_t)o));
    uint64_t lo = rd32(b, o);
    uint64_t hi = rd32(b, o + 4);
    return lo | (hi << 32);
}

static void wr32(Bytes& b, size_t o, uint32_t v) {
    if (o + 4 > b.size()) fail("write32 out of bounds at " + hx((uint32_t)o));
    b[o] = (uint8_t)(v & 0xFF);
    b[o + 1] = (uint8_t)((v >> 8) & 0xFF);
    b[o + 2] = (uint8_t)((v >> 16) & 0xFF);
    b[o + 3] = (uint8_t)((v >> 24) & 0xFF);
}

static size_t alignUp(size_t v, size_t a) {
    if (a <= 1) return v;
    return (v + a - 1) / a * a;
}

static std::string lowerAscii(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Normalize a path so that two spellings of the same file compare equal.
// A plain string comparison is not enough: "x.exe" and ".\x.exe" or
// "E:\dir\x.exe" and "E:/dir/x.exe" denote the same file, and the output
// path must never resolve to the input path.
static std::string canonicalPath(const std::string& p) {
    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(p, ec);
    if (ec) abs = std::filesystem::path(p);
    std::filesystem::path norm = std::filesystem::weakly_canonical(abs, ec);
    if (ec) norm = abs.lexically_normal();
    return lowerAscii(norm.generic_string());
}

static std::string readCString(const Bytes& b, size_t off, size_t maxLen, const char* what) {
    std::string s;
    for (size_t i = 0; i < maxLen; ++i) {
        if (off + i >= b.size()) fail(std::string(what) + ": string out of bounds");
        char c = (char)b[off + i];
        if (c == 0) return s;
        s.push_back(c);
    }
    fail(std::string(what) + ": unterminated string");
    return s;
}

static std::string readAsciiFixed(const Bytes& b, size_t off, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        if (off + i >= b.size()) fail("section name out of bounds");
        char c = (char)b[off + i];
        if (c == 0) break;
        s.push_back(c);
    }
    return s;
}

struct Section {
    std::string name;
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;
    uint32_t rawSize = 0;
    uint32_t rawPtr = 0;
    uint32_t characteristics = 0;
    size_t headerOff = 0;
};

struct TypeInfo {
    uint32_t rid = 0;
    std::string name;
    std::string ns;
    uint32_t fieldList = 0;
    uint32_t methodList = 0;
    uint32_t nextFieldList = 0;
    uint32_t nextMethodList = 0;
    size_t rowOff = 0;
};

struct MethodInfo {
    uint32_t rid = 0;
    uint32_t rva = 0;
    uint16_t implFlags = 0;
    uint16_t flags = 0;
    std::string name;
    uint32_t sigIdx = 0;
    uint32_t paramList = 0;
    size_t rowOff = 0;
    int typeIndex = -1;
};

struct FieldInfo {
    uint32_t rid = 0;
    uint16_t flags = 0;
    std::string name;
    uint32_t sigIdx = 0;
    size_t rowOff = 0;
    int typeIndex = -1;
};

struct BodyInfo {
    size_t bodyOff = 0;
    size_t codeOff = 0;
    uint32_t codeSize = 0;
    uint16_t maxStack = 0;
    uint32_t localSig = 0;
    size_t headerSize = 0;
    bool fat = false;
    bool hasSections = false;   // exception table present
};

class PEImage {
public:
    Bytes& data;

    size_t peOff = 0;
    size_t optOff = 0;
    size_t secTable = 0;
    uint16_t numSections = 0;
    uint16_t optSize = 0;
    uint16_t magic = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint32_t sizeOfImage = 0;

    size_t cliOff = 0;
    size_t mdOff = 0;
    uint32_t mdSize = 0;

    size_t stringsOff = 0, stringsSize = 0;
    size_t blobOff = 0, blobSize = 0;
    size_t usOff = 0, usSize = 0;
    std::map<uint32_t, std::string> usStrings; // #US blob offset -> raw UTF-16LE bytes
    size_t tablesOff = 0, tablesSize = 0;

    uint8_t heapSizes = 0;
    uint64_t valid = 0;
    uint32_t rows[64] = {0};
    uint32_t tableStart[64] = {0};
    uint32_t tableRowSize[64] = {0};

    uint32_t strSize = 2, guidSize = 2, blobSizeIdx = 2;
    uint32_t typeDefStart = 0, typeDefRowSize = 0;
    uint32_t fieldStart = 0, fieldRowSize = 0;
    uint32_t methodDefStart = 0, methodDefRowSize = 0;

    std::vector<Section> sections;
    std::vector<TypeInfo> types;
    std::vector<MethodInfo> methods;
    std::vector<FieldInfo> fields;

    explicit PEImage(Bytes& d) : data(d) { parse(); }

    size_t rvaToOff(uint32_t rva) const {
        for (const auto& s : sections) {
            uint32_t span = std::max(s.virtualSize, s.rawSize);
            if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
                size_t off = (size_t)s.rawPtr + (rva - s.virtualAddress);
                if (off >= data.size()) fail("RVA maps past end of file: " + hx(rva));
                return off;
            }
        }
        fail("RVA not mapped: " + hx(rva));
        return 0;
    }

    uint32_t readIndex(size_t off, uint32_t size) const {
        if (size == 2) return rd16(data, off);
        if (size == 4) return rd32(data, off);
        fail("unsupported index size");
        return 0;
    }

    uint32_t idxSize(int table) const {
        return rows[table] < 65536 ? 2u : 4u;
    }

    uint32_t codedSize(int tagBits, std::initializer_list<int> tables) const {
        uint32_t maxRows = 0;
        for (int t : tables) maxRows = std::max(maxRows, rows[t]);
        return maxRows < (1u << (16 - tagBits)) ? 2u : 4u;
    }

    uint32_t rowSize(int t) const {
        switch (t) {
            case 0x00: return 2 + strSize + guidSize * 3;
            case 0x01: return codedSize(2, {0x00, 0x1A, 0x23, 0x01}) + strSize * 2;
            case 0x02: return 4 + strSize * 2 + codedSize(2, {0x02, 0x01, 0x1B}) +
                              idxSize(0x04) + idxSize(0x06);
            case 0x03: return idxSize(0x04);
            case 0x04: return 2 + strSize + blobSizeIdx;
            case 0x05: return idxSize(0x06);
            case 0x06: return 4 + 2 + 2 + strSize + blobSizeIdx + idxSize(0x08);
            default: return 0; // not needed for the tables we inspect
        }
    }

    std::string str(uint32_t idx) const {
        if (idx == 0) return "";
        if (idx >= stringsSize) fail("string index out of range: " + hx(idx));
        return readCString(data, stringsOff + idx, stringsSize - idx, "#Strings");
    }

    void parse() {
        if (data.size() < 0x40) fail("file too small");
        peOff = rd32(data, 0x3C);
        if (peOff + 24 > data.size()) fail("bad PE offset");
        if (rd32(data, peOff) != 0x00004550) fail("not a PE file");
        numSections = rd16(data, peOff + 6);
        optSize = rd16(data, peOff + 20);
        optOff = peOff + 24;
        secTable = optOff + optSize;
        if (secTable + (size_t)numSections * 40 > data.size()) fail("section table out of bounds");
        magic = rd16(data, optOff);
        if (magic != 0x10B && magic != 0x20B) fail("unsupported PE optional header");
        sectionAlignment = rd32(data, optOff + 32);
        fileAlignment = rd32(data, optOff + 36);
        sizeOfImage = rd32(data, optOff + 56);

        sections.reserve(numSections);
        for (uint16_t i = 0; i < numSections; ++i) {
            size_t h = secTable + (size_t)i * 40;
            Section s;
            s.headerOff = h;
            s.name = readAsciiFixed(data, h, 8);
            s.virtualSize = rd32(data, h + 8);
            s.virtualAddress = rd32(data, h + 12);
            s.rawSize = rd32(data, h + 16);
            s.rawPtr = rd32(data, h + 20);
            s.characteristics = rd32(data, h + 36);
            sections.push_back(s);
        }

        size_t ddOff = optOff + (magic == 0x20B ? 0x70 : 0x60);
        uint32_t cliRva = rd32(data, ddOff + 14 * 8);
        if (cliRva == 0) fail("no CLI header (not a managed assembly)");
        cliOff = rvaToOff(cliRva);
        uint32_t mdRva = rd32(data, cliOff + 8);
        mdSize = rd32(data, cliOff + 12);
        mdOff = rvaToOff(mdRva);

        uint32_t verLen = rd32(data, mdOff + 12);
        size_t p = mdOff + 16 + alignUp(verLen, 4);
        uint16_t nStreams = rd16(data, p + 2);
        p += 4;
        for (uint16_t i = 0; i < nStreams; ++i) {
            uint32_t off = rd32(data, p);
            uint32_t size = rd32(data, p + 4);
            p += 8;
            size_t nameStart = p;
            while (p < data.size() && data[p] != 0) ++p;
            if (p >= data.size()) fail("metadata stream name out of bounds");
            std::string name((const char*)&data[nameStart], p - nameStart);
            ++p;
            p = alignUp(p, 4);
            size_t abs = mdOff + off;
            if (name == "#Strings") { stringsOff = abs; stringsSize = size; }
            else if (name == "#Blob") { blobOff = abs; blobSize = size; }
            else if (name == "#US") { usOff = abs; usSize = size; }
            else if (name == "#~" || name == "#-") { tablesOff = abs; tablesSize = size; }
        }
        if (stringsOff == 0 || tablesOff == 0) fail("missing metadata heaps");

        heapSizes = data[tablesOff + 6];
        valid = rd64(data, tablesOff + 8);
        strSize = (heapSizes & 1) ? 4 : 2;
        guidSize = (heapSizes & 2) ? 4 : 2;
        blobSizeIdx = (heapSizes & 4) ? 4 : 2;

        p = tablesOff + 24;
        for (int i = 0; i < 64; ++i) {
            if (valid & (1ULL << i)) {
                rows[i] = rd32(data, p);
                p += 4;
            }
        }

        // Compute table starts. We only need tables 0x00..0x06, but rowSize()
        // for those uses the global row counts, so the starts are exact.
        for (int i = 0; i < 64; ++i) {
            if (!(valid & (1ULL << i))) continue;
            tableStart[i] = (uint32_t)p;
            tableRowSize[i] = rowSize(i);
            p += (size_t)tableRowSize[i] * rows[i];
        }
        typeDefStart = tableStart[0x02];
        typeDefRowSize = tableRowSize[0x02];
        fieldStart = tableStart[0x04];
        fieldRowSize = tableRowSize[0x04];
        methodDefStart = tableStart[0x06];
        methodDefRowSize = tableRowSize[0x06];
        if (!typeDefStart || !fieldStart || !methodDefStart) fail("missing metadata tables");

        parseTypes();
        parseFields();
        parseMethods();
    }

    void parseTypes() {
        types.reserve(rows[0x02]);
        uint32_t extSize = codedSize(2, {0x02, 0x01, 0x1B});
        uint32_t fieldIdxSize = idxSize(0x04);
        uint32_t methodIdxSize = idxSize(0x06);
        for (uint32_t i = 0; i < rows[0x02]; ++i) {
            size_t o = typeDefStart + (size_t)i * typeDefRowSize;
            TypeInfo t;
            t.rid = i + 1;
            t.rowOff = o;
            t.name = str(readIndex(o + 4, strSize));
            t.ns = str(readIndex(o + 4 + strSize, strSize));
            size_t fieldListOff = o + 4 + 2 * strSize + extSize;
            t.fieldList = readIndex(fieldListOff, fieldIdxSize);
            t.methodList = readIndex(fieldListOff + fieldIdxSize, methodIdxSize);
            types.push_back(t);
        }
        for (size_t i = 0; i < types.size(); ++i) {
            types[i].nextFieldList = (i + 1 < types.size()) ? types[i + 1].fieldList : rows[0x04] + 1;
            types[i].nextMethodList = (i + 1 < types.size()) ? types[i + 1].methodList : rows[0x06] + 1;
            if (types[i].nextFieldList < types[i].fieldList) fail("bad field list range");
            if (types[i].nextMethodList < types[i].methodList) fail("bad method list range");
        }
    }

    void parseFields() {
        fields.reserve(rows[0x04]);
        for (uint32_t rid = 1; rid <= rows[0x04]; ++rid) {
            size_t o = fieldStart + (size_t)(rid - 1) * fieldRowSize;
            FieldInfo f;
            f.rid = rid;
            f.rowOff = o;
            f.flags = rd16(data, o);
            f.name = str(readIndex(o + 2, strSize));
            f.sigIdx = readIndex(o + 2 + strSize, blobSizeIdx);
            fields.push_back(f);
        }
        for (size_t ti = 0; ti < types.size(); ++ti) {
            uint32_t a = types[ti].fieldList;
            uint32_t b = types[ti].nextFieldList;
            if (a == 0) continue;
            for (uint32_t rid = a; rid < b && rid <= rows[0x04]; ++rid) {
                fields[rid - 1].typeIndex = (int)ti;
            }
        }
    }

    void parseMethods() {
        methods.reserve(rows[0x06]);
        for (uint32_t rid = 1; rid <= rows[0x06]; ++rid) {
            size_t o = methodDefStart + (size_t)(rid - 1) * methodDefRowSize;
            MethodInfo m;
            m.rid = rid;
            m.rowOff = o;
            m.rva = rd32(data, o);
            m.implFlags = rd16(data, o + 4);
            m.flags = rd16(data, o + 6);
            m.name = str(readIndex(o + 8, strSize));
            m.sigIdx = readIndex(o + 8 + strSize, blobSizeIdx);
            m.paramList = readIndex(o + 8 + strSize + blobSizeIdx, idxSize(0x08));
            methods.push_back(m);
        }
        for (size_t ti = 0; ti < types.size(); ++ti) {
            uint32_t a = types[ti].methodList;
            uint32_t b = types[ti].nextMethodList;
            if (a == 0) continue;
            for (uint32_t rid = a; rid < b && rid <= rows[0x06]; ++rid) {
                methods[rid - 1].typeIndex = (int)ti;
            }
        }
    }

    int findType(const std::string& fullName) const {
        for (size_t i = 0; i < types.size(); ++i) {
            std::string n = types[i].ns.empty() ? types[i].name : types[i].ns + "." + types[i].name;
            if (n == fullName) return (int)i;
        }
        return -1;
    }

    int findMethod(int typeIndex, const std::string& name) const {
        for (size_t i = 0; i < methods.size(); ++i) {
            if (methods[i].typeIndex == typeIndex && methods[i].name == name) return (int)i;
        }
        return -1;
    }

    int findField(int typeIndex, const std::string& name) const {
        for (size_t i = 0; i < fields.size(); ++i) {
            if (fields[i].typeIndex == typeIndex && fields[i].name == name) return (int)i;
        }
        return -1;
    }

    // ---------------- TypeRef / MemberRef lookups ----------------
    bool typeRefName(uint32_t rid, std::string& ns, std::string& name) const {
        size_t start = 0;
        uint32_t rs = 0;
        if (!tableInfo(0x01, start, rs)) return false;
        if (rid == 0 || rid > rows[0x01]) return false;
        size_t o = start + (size_t)(rid - 1) * rs;
        uint32_t scopeSz = codedSize(2, {0x00, 0x1A, 0x23, 0x01});
        name = str(readIndex(o + scopeSz, strSize));
        ns = str(readIndex(o + scopeSz + strSize, strSize));
        return true;
    }

    uint32_t findTypeRef(const std::string& fullName) const {
        for (uint32_t rid = 1; rid <= rows[0x01]; ++rid) {
            std::string ns, name;
            if (!typeRefName(rid, ns, name)) continue;
            std::string full = ns.empty() ? name : ns + "." + name;
            if (full == fullName) return 0x01000000u | rid;
        }
        return 0;
    }

    bool memberRefInfo(uint32_t rid, std::string& parentName, std::string& name,
                       uint32_t& sigIndex) const {
        size_t start = 0;
        uint32_t rs = 0;
        if (!tableInfo(0x0A, start, rs)) return false;
        if (rid == 0 || rid > rows[0x0A]) return false;
        uint32_t csz = codedSize(3, {0x02, 0x01, 0x19, 0x06, 0x1B});
        size_t o = start + (size_t)(rid - 1) * rs;
        uint32_t parent = readIndex(o, csz);
        uint32_t tag = parent & 7;
        uint32_t prid = parent >> 3;
        parentName.clear();
        if (tag == 1) {
            std::string ns, nm;
            if (typeRefName(prid, ns, nm)) parentName = ns.empty() ? nm : ns + "." + nm;
        } else if (tag == 0 && prid >= 1 && prid <= types.size()) {
            const TypeInfo& t = types[prid - 1];
            parentName = t.ns.empty() ? t.name : t.ns + "." + t.name;
        } else {
            parentName = "?";
        }
        name = str(readIndex(o + csz, strSize));
        sigIndex = readIndex(o + csz + strSize, blobSizeIdx);
        return true;
    }

    uint32_t findMemberRef(const std::string& parentFullName, const std::string& memberName) const {
        for (uint32_t rid = 1; rid <= rows[0x0A]; ++rid) {
            std::string parent, name;
            uint32_t sigIndex = 0;
            if (!memberRefInfo(rid, parent, name, sigIndex)) continue;
            if (parent == parentFullName && name == memberName) return 0x0A000000u | rid;
        }
        return 0;
    }

    // ---------------- #US user-string heap ----------------
    // The #US heap stores every UTF-16 string literal used by ldstr.
    // A blob starts with a compressed length (1 or 2 bytes) that also counts
    // the trailing "special" flag byte, so the text itself is (len - 1) bytes.
    // The metadata token of a blob is 0x70000000 | <offset of the length byte>.
    void readUsHeap() {
        usStrings.clear();
        if (usOff == 0 || usSize == 0) return;
        size_t o = 1; // offset 0 always holds a zero-length blob
        while (o < usSize) {
            uint32_t len = data[usOff + o];
            size_t hdr = 1;
            if (len & 0x80) {
                if (o + 1 >= usSize) break;
                len = ((len & 0x7F) << 8) | data[usOff + o + 1];
                hdr = 2;
            }
            if (len == 0) { o += 1; continue; }
            if (o + hdr + len > usSize) break;
            usStrings[(uint32_t)o] = std::string((const char*)&data[usOff + o + hdr], len - 1);
            o += hdr + len;
        }
    }

    // Raw UTF-16LE bytes of the blob that starts at <blobOff>.
    bool usRawAt(uint32_t blobOff, std::string& out) const {
        auto it = usStrings.find(blobOff);
        if (it == usStrings.end()) return false;
        out = it->second;
        return true;
    }

    // Metadata token of the #US blob whose UTF-16LE text equals <utf16le>.
    uint32_t findUsToken(const std::string& utf16le) const {
        for (const auto& kv : usStrings) {
            if (kv.second == utf16le) return 0x70000000u | kv.first;
        }
        return 0;
    }

    // ---------------- #Blob heap ----------------
    bool readBlob(uint32_t index, Bytes& out) const {
        out.clear();
        if (blobOff == 0) return false;
        size_t o = blobOff + index;
        if (o >= data.size()) return false;
        uint32_t len = data[o++];
        if (len & 0x80) {
            if (len & 0xC0) {
                if (o + 3 >= data.size()) return false;
                len = ((uint32_t)(len & 0x1F) << 24) | ((uint32_t)data[o] << 16) |
                      ((uint32_t)data[o + 1] << 8) | data[o + 2];
                o += 3;
            } else {
                if (o + 1 >= data.size()) return false;
                len = ((uint32_t)(len & 0x3F) << 8) | data[o];
                o += 1;
            }
        }
        if (o + len > data.size()) return false;
        out.assign(data.begin() + o, data.begin() + o + len);
        return true;
    }

    // Row sizes of the metadata tables that follow the ones used so far.  They
    // are only needed to locate the MemberRef table (for call signatures).
    uint32_t rowSizeOf(int t) const {
        switch (t) {
            case 0x08: return 2 + 2 + strSize;                       // Param
            case 0x09: return idxSize(0x02) + codedSize(2, {0x02, 0x01, 0x1B});
            case 0x0A: return codedSize(3, {0x02, 0x01, 0x19, 0x06, 0x1B}) + strSize + blobSizeIdx;
            case 0x0B: return 2 + codedSize(2, {0x04, 0x08, 0x16}) + blobSizeIdx;
            default: return 0;
        }
    }

    // Locate a table by number.  The metadata tables are stored back to back,
    // so the start of a table is the sum of the sizes of all previous ones.
    bool tableInfo(int table, size_t& start, uint32_t& rsOut) const {
        size_t p = tablesOff + 24;
        // the row counts of all present tables come first
        for (int i = 0; i < 64; ++i)
            if (valid & (1ULL << i)) p += 4;
        for (int i = 0; i < 64; ++i) {
            if (!(valid & (1ULL << i))) continue;
            uint32_t rs = (i <= 0x06) ? rowSize(i) : rowSizeOf(i);
            if (rs == 0) return false;
            if (i == table) { start = p; rsOut = rs; return true; }
            p += (size_t)rs * rows[i];
        }
        return false;
    }

    // Signature blob of a MemberRef row.
    bool memberRefSigIndex(uint32_t rid, uint32_t& sigIndex) const {
        size_t start = 0; uint32_t rs = 0;
        if (!tableInfo(0x0A, start, rs)) return false;
        if (rid == 0 || rid > rows[0x0A]) return false;
        size_t o = start + (size_t)(rid - 1) * rs;
        sigIndex = readIndex(o + codedSize(3, {0x02, 0x01, 0x19, 0x06, 0x1B}) + strSize, blobSizeIdx);
        return true;
    }

    // Signature blob of a MethodDef row.
    uint32_t methodSigIndex(uint32_t methodRid) const {
        size_t o = methodDefStart + (size_t)(methodRid - 1) * methodDefRowSize;
        return readIndex(o + 8 + strSize, blobSizeIdx);
    }

    BodyInfo bodyOf(const MethodInfo& m) const {
        if (m.rva == 0) fail("method has no body: " + m.name);
        BodyInfo b;
        b.bodyOff = rvaToOff(m.rva);
        uint16_t flags = rd16(data, b.bodyOff);
        if ((flags & 0x3) == 0x2) {
            b.fat = false;
            b.headerSize = 1;
            b.codeSize = flags >> 2;
            b.maxStack = 8;
            b.localSig = 0;
        } else if ((flags & 0x3) == 0x3) {
            b.fat = true;
            b.headerSize = (size_t)((flags >> 12) & 0xF) * 4;
            if (b.headerSize < 12) b.headerSize = 12;
            b.maxStack = rd16(data, b.bodyOff + 2);
            b.codeSize = rd32(data, b.bodyOff + 4);
            b.localSig = rd32(data, b.bodyOff + 8);
            b.hasSections = (flags & 0x08) != 0;
        } else {
            fail("unsupported method header flags for " + m.name);
        }
        b.codeOff = b.bodyOff + b.headerSize;
        if (b.codeOff + b.codeSize > data.size()) fail("method body out of bounds: " + m.name);
        return b;
    }
};

// ---------------------------------------------------------------------------
// IL decoding
//
// A single decoder for the whole tool.  It knows the length of every CIL
// opcode, so patch sites are found by *shape* (instruction sequences) instead
// of hardcoded file offsets.  This is what lets the tool survive a recompiled
// binary where every offset and method-body size has moved.
// ---------------------------------------------------------------------------

struct IlInstr {
    size_t off = 0;        // offset from the first byte of the IL
    uint16_t op = 0;       // 0xFE-prefixed opcodes are reported as 0xFE00 | b
    uint32_t operand = 0;  // token / index / branch delta / switch case count
    size_t size = 0;       // total size in bytes
};

// Operand size of a one-byte opcode, in bytes.
static int ilOperandSize(uint8_t op) {
    switch (op) {
        case 0x0E: case 0x0F: case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x1F: case 0xDE:
        case 0x2B: case 0x2C: case 0x2D: case 0x2E: case 0x2F:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
        case 0x36: case 0x37:
            return 1;
        case 0x20: case 0x22: case 0x27: case 0x28: case 0x29: case 0x45:
        case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D:
        case 0x3E: case 0x3F: case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44:
        case 0x6F: case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
        case 0x75: case 0x79: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
        case 0x7F: case 0x80: case 0x81: case 0x8C: case 0x8D: case 0x8F:
        case 0xA3: case 0xA4: case 0xA5: case 0xC2: case 0xC6: case 0xD0:
        case 0xDD:
            return 4;
        case 0x21: case 0x23:
            return 8;
        default:
            return 0;
    }
}

static bool disassemble(const Bytes& code, std::vector<IlInstr>& out, std::string& err) {
    out.clear();
    size_t p = 0;
    while (p < code.size()) {
        IlInstr in;
        in.off = p;
        uint8_t op = code[p];
        if (op == 0xFE) {
            if (p + 2 > code.size()) { err = "truncated prefix opcode"; return false; }
            uint8_t b = code[p + 1];
            in.op = (uint16_t)(0xFE00u | b);
            int osz = 0;
            switch (b) {
                case 0x06: case 0x07: case 0x15: case 0x16: case 0x1C: osz = 4; break;
                case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E: osz = 2; break;
                case 0x12: case 0x19: osz = 1; break;
                default: osz = 0; break;
            }
            if (p + 2 + (size_t)osz > code.size()) { err = "truncated prefix operand"; return false; }
            if (osz == 4) in.operand = rd32(code, p + 2);
            else if (osz == 2) in.operand = rd16(code, p + 2);
            else if (osz == 1) in.operand = code[p + 2];
            in.size = 2 + (size_t)osz;
        } else {
            in.op = op;
            if (op == 0x45) {
                if (p + 5 > code.size()) { err = "truncated switch"; return false; }
                uint32_t n = rd32(code, p + 1);
                if (n > 0x10000u || p + 5 + (size_t)4 * n > code.size()) {
                    err = "bad switch table";
                    return false;
                }
                in.operand = n;
                in.size = 5 + (size_t)4 * n;
            } else {
                int osz = ilOperandSize(op);
                if (p + 1 + (size_t)osz > code.size()) { err = "truncated operand"; return false; }
                if (osz == 1) in.operand = code[p + 1];
                else if (osz == 4 || osz == 8) in.operand = rd32(code, p + 1);
                in.size = 1 + (size_t)osz;
            }
        }
        out.push_back(in);
        p += in.size;
    }
    return true;
}

static bool disassemble(const Bytes& code, std::vector<IlInstr>& out) {
    std::string err;
    return disassemble(code, out, err);
}

// Signed offset carried by a branch instruction.
static int32_t ilBranchDelta(const IlInstr& in) {
    if (in.op == 0xDE || (in.op >= 0x2B && in.op <= 0x37))
        return (int8_t)(uint8_t)in.operand;
    return (int32_t)in.operand;
}

static bool ilIsBranch(uint16_t op) {
    return (op >= 0x2B && op <= 0x44) || op == 0xDD || op == 0xDE || op == 0x45;
}

static bool ilIsCondBranch(uint16_t op) {
    return (op >= 0x2C && op <= 0x37) || (op >= 0x39 && op <= 0x44) || op == 0x45;
}

// Absolute offset a branch instruction jumps to.
static size_t ilBranchTarget(const IlInstr& in) {
    return (size_t)((long)in.off + (long)in.size + (long)ilBranchDelta(in));
}

struct LoaderTokens {
    uint32_t controlInit = 0;
    uint32_t loadMinecraft = 0;
    uint32_t panLoad = 0;
    uint32_t panAllBack = 0;
    uint32_t lambda = 0;
    uint32_t actionCtor = 0;
    uint32_t pageLoaderInit = 0;
    uint32_t dlLoaderField = 0;
    Bytes priorityBytes;   // the "ldc.i4 <priority>" instruction, copied verbatim
};

static uint32_t methodToken(const MethodInfo& m) { return 0x06000000u | m.rid; }
static uint32_t fieldToken(const FieldInfo& f) { return 0x04000000u | f.rid; }

// Build the UTF-16LE form of a few code points (for #US blob lookups).
static std::string utf16le(std::initializer_list<uint16_t> cps) {
    std::string s;
    for (uint16_t c : cps) {
        s.push_back((char)(c & 0xFF));
        s.push_back((char)((c >> 8) & 0xFF));
    }
    return s;
}

// Locate everything LoaderInit needs by the *shape* of its body, never by an
// offset: the body is "ControlInit(); three getters; <loader field> = Nothing;
// PageLoaderInit(null, New Action(AddressOf lambda), <priority>)".  Every token
// is either resolved by name or taken from the instruction that uses it, and
// the two sources are cross checked.
static LoaderTokens extractLoaderTokens(const PEImage& pe, int typeIndex, const Bytes& code,
                                        uint32_t dlLoaderField) {
    std::vector<IlInstr> ops;
    if (!disassemble(code, ops)) fail("LoaderInit: the body does not decode");
    if (ops.size() < 10) fail("LoaderInit: the body is too short");

    LoaderTokens t;
    if (ops[0].op != 0x02 || ops[1].op != 0x28)
        fail("LoaderInit: ControlInit call not found at the beginning of the body");
    {
        int mi = pe.findMethod(typeIndex, "ControlInit");
        if (mi < 0) fail("LoaderInit: PCL.PageDownloadInstall.ControlInit not found");
        if (methodToken(pe.methods[mi]) != ops[1].operand)
            fail("LoaderInit: the first call is not ControlInit");
        t.controlInit = ops[1].operand;
    }

    // "ldarg.0" (the receiver of the PageLoaderInit call) followed by three
    // "ldarg.0 / callvirt get_X" pairs
    if (ops[2].op != 0x02) fail("LoaderInit: unexpected instruction after ControlInit");
    const char* getters[3] = {"get_LoadMinecraft", "get_PanLoad", "get_PanAllBack"};
    uint32_t* targets[3] = {&t.loadMinecraft, &t.panLoad, &t.panAllBack};
    for (int k = 0; k < 3; ++k) {
        const IlInstr& a = ops[(size_t)(3 + 2 * k)];
        const IlInstr& b = ops[(size_t)(4 + 2 * k)];
        if (a.op != 0x02 || b.op != 0x6F)
            fail(std::string("LoaderInit: call to ") + getters[k] + " not found");
        int mi = pe.findMethod(typeIndex, getters[k]);
        if (mi < 0) fail(std::string("LoaderInit: ") + getters[k] + " not found");
        if (methodToken(pe.methods[mi]) != b.operand)
            fail(std::string("LoaderInit: unexpected call where ") + getters[k] + " was expected");
        *targets[k] = b.operand;
    }

    // The patch resets the download list loader so the page rebuilds it.  The
    // field is resolved by name in the caller, only its token is needed here.
    t.dlLoaderField = dlLoaderField;

    // tail: ldarg.0 / ldftn lambda / newobj Action / ldnull / ldc / call / ret
    size_t n = ops.size();
    if (ops[n - 1].op != 0x2A) fail("LoaderInit: the body does not end with ret");
    if (ops[n - 2].op != 0x28) fail("LoaderInit: the PageLoaderInit call was not found");
    if (ops[n - 3].op < 0x15 || ops[n - 3].op > 0x20)
        fail("LoaderInit: the priority argument was not found");
    if (ops[n - 4].op != 0x14) fail("LoaderInit: unexpected argument before the priority");
    if (ops[n - 5].op != 0x73) fail("LoaderInit: New Action(...) was not found");
    if (ops[n - 6].op != 0xFE06) fail("LoaderInit: the loader lambda (ldftn) was not found");
    t.pageLoaderInit = ops[n - 2].operand;
    t.actionCtor = ops[n - 5].operand;
    t.lambda = ops[n - 6].operand;
    // the priority is re-emitted verbatim, so a different constant still works
    t.priorityBytes.assign(code.begin() + (long)ops[n - 3].off,
                           code.begin() + (long)(ops[n - 3].off + ops[n - 3].size));

    std::cout << "  LoaderInit tokens:\n"
              << "    ControlInit       " << hx8(t.controlInit) << "\n"
              << "    get_LoadMinecraft " << hx8(t.loadMinecraft) << "\n"
              << "    get_PanLoad       " << hx8(t.panLoad) << "\n"
              << "    get_PanAllBack    " << hx8(t.panAllBack) << "\n"
              << "    _Lambda$__R3-4    " << hx8(t.lambda) << "\n"
              << "    Action ctor       " << hx8(t.actionCtor) << "\n"
              << "    PageLoaderInit    " << hx8(t.pageLoaderInit) << "\n"
              << "    DlClientListLoader " << hx8(t.dlLoaderField) << "\n";
    return t;
}

static Bytes buildLoaderPatch(const LoaderTokens& t) {
    Bytes c;
    auto b = [&](uint8_t v) { c.push_back(v); };
    auto i32 = [&](uint32_t v) {
        b((uint8_t)(v & 0xFF));
        b((uint8_t)((v >> 8) & 0xFF));
        b((uint8_t)((v >> 16) & 0xFF));
        b((uint8_t)((v >> 24) & 0xFF));
    };
    b(0x02);
    b(0x28); i32(t.controlInit);
    b(0x02); b(0x02); b(0x6F); i32(t.loadMinecraft);
    b(0x02); b(0x6F); i32(t.panLoad);
    b(0x02); b(0x6F); i32(t.panAllBack);
    b(0x14);
    b(0x7E); i32(t.dlLoaderField);
    b(0x02);
    b(0xFE); b(0x06); i32(t.lambda);
    b(0x73); i32(t.actionCtor);
    b(0x14);
    c.insert(c.end(), t.priorityBytes.begin(), t.priorityBytes.end());
    b(0x28); i32(t.pageLoaderInit);
    b(0x2A);
    return c;
}

struct InstallerTokens {
    uint32_t curseForge = 0;
    uint32_t hmcl = 0;
    uint32_t mmc = 0;
    uint32_t mcbbs = 0;
    uint32_t modrinth = 0;
    uint32_t launcherPack = 0;
    uint32_t compress = 0;
};

static InstallerTokens resolveInstallers(const PEImage& pe, int modType) {
    struct Req { const char* name; uint32_t* out; };
    InstallerTokens t;
    Req reqs[] = {
        {"InstallPackCurseForge", &t.curseForge},
        {"InstallPackHMCL", &t.hmcl},
        {"InstallPackMMC", &t.mmc},
        {"InstallPackMCBBS", &t.mcbbs},
        {"InstallPackModrinth", &t.modrinth},
        {"InstallPackLauncherPack", &t.launcherPack},
        {"InstallPackCompress", &t.compress},
    };
    for (const auto& r : reqs) {
        int mi = pe.findMethod(modType, r.name);
        if (mi < 0) fail(std::string("installer method not found: ") + r.name);
        *r.out = methodToken(pe.methods[mi]);
        std::cout << "  " << r.name << " " << hx8(*r.out) << "\n";
    }
    return t;
}

// ---------------------------------------------------------------------------
// Reading a method signature
//
// The CLR verifier requires that the value passed to a call matches the
// declared parameter type exactly (an object is not assignable to a class
// parameter).  The patch therefore has to know the real parameter type of the
// method it calls - it is taken from the callee's own signature blob, never
// guessed.
// ---------------------------------------------------------------------------

static bool readCompressed(const Bytes& b, size_t& i, uint32_t& v) {
    if (i >= b.size()) return false;
    uint8_t x = b[i];
    if ((x & 0x80) == 0) { v = x; i += 1; return true; }
    if ((x & 0xC0) == 0x80) {
        if (i + 1 >= b.size()) return false;
        v = ((uint32_t)(x & 0x3F) << 8) | b[i + 1];
        i += 2;
        return true;
    }
    if ((x & 0xE0) == 0xC0) {
        if (i + 3 >= b.size()) return false;
        v = ((uint32_t)(x & 0x1F) << 24) | ((uint32_t)b[i + 1] << 16) |
            ((uint32_t)b[i + 2] << 8) | b[i + 3];
        i += 4;
        return true;
    }
    return false;
}

// A TypeDefOrRef coded index becomes a metadata token.
static uint32_t typeDefOrRefToken(uint32_t idx) {
    switch (idx & 3) {
        case 0: return 0x02000000u | (idx >> 2);   // TypeDef
        case 1: return 0x01000000u | (idx >> 2);   // TypeRef
        default: return 0x1B000000u | (idx >> 2);  // TypeSpec
    }
}

// The shape of a call target: how many arguments it takes, whether it has a
// receiver and whether it returns a value.
struct CallSig {
    uint32_t paramCount = 0;
    bool hasThis = false;
    bool returnsValue = false;
    std::vector<uint32_t> paramTypes;  // type id, 0 = primitive / unknown
};

// Read one type from a signature blob.
//
// A class or value type is reported as its metadata token, System.Object as
// 0x1C and System.String as 0x0E (the respective element type values), every
// other type - including arrays - as 0.  Compound types are still parsed
// completely so that the following parameters stay aligned.
static bool readSigType(const Bytes& sig, size_t& i, uint32_t& id) {
    id = 0;
    if (i >= sig.size()) return false;
    uint8_t e = sig[i++];
    switch (e) {
        case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06:
        case 0x07: case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C:
        case 0x0D: case 0x16: case 0x18: case 0x19: case 0x1B:
            if (e == 0x01) id = 0x01;                     // void
            return true;                                  // primitives
        case 0x0E: id = 0x0E; return true;                // string
        case 0x1C: id = 0x1C; return true;                // object
        case 0x0F: case 0x10: case 0x1D:                  // ptr / byref / szarray
            return readSigType(sig, i, id);
        case 0x11: case 0x12: {                           // valuetype / class
            uint32_t idx = 0;
            if (!readCompressed(sig, i, idx)) return false;
            id = typeDefOrRefToken(idx);
            return true;
        }
        case 0x13: case 0x14: case 0x1E: {                // var / mvar
            uint32_t n = 0;
            return readCompressed(sig, i, n);
        }
        case 0x15: {                                      // genericinst
            uint32_t dummy = 0;
            if (!readSigType(sig, i, dummy)) return false;
            uint32_t n = 0;
            if (!readCompressed(sig, i, n)) return false;
            for (uint32_t k = 0; k < n; ++k)
                if (!readSigType(sig, i, dummy)) return false;
            return true;
        }
        case 0x1F: case 0x20: {                           // cmod_reqd / cmod_opt
            uint32_t idx = 0;
            if (!readCompressed(sig, i, idx)) return false;
            return readSigType(sig, i, id);
        }
        case 0x45:                                        // pinned
            return readSigType(sig, i, id);
        default:
            return false;
    }
}

static bool parseSig(const Bytes& sig, CallSig& out) {
    out = CallSig();
    if (sig.empty()) return false;
    size_t i = 1;  // calling convention
    out.hasThis = (sig[0] & 0x20) != 0;
    uint32_t n = 0;
    if (!readCompressed(sig, i, n)) return false;
    out.paramCount = n;
    uint32_t ret = 0;
    if (!readSigType(sig, i, ret)) return false;
    out.returnsValue = (ret != 0x01);
    for (uint32_t k = 0; k < n; ++k) {
        uint32_t tok = 0;
        if (!readSigType(sig, i, tok)) return false;
        out.paramTypes.push_back(tok);
    }
    return true;
}

// ---------------------------------------------------------------------------
// A small IL verifier
//
// Before a rebuilt method is written it is verified: the stack depth and the
// argument types of every call have to match the callee's signature, every
// branch target has to land on an instruction boundary and the stack has to be
// empty at every ret.  An opcode the checker does not model is an error - the
// tool never writes IL it could not verify.
// ---------------------------------------------------------------------------

// Resolve the signature of a call target (MethodDef or MemberRef).
static bool resolveCallSig(const PEImage& pe, uint32_t token, CallSig& out) {
    uint32_t table = token >> 24;
    uint32_t rid = token & 0xFFFFFF;
    Bytes sig;
    if (table == 0x06) {
        if (rid == 0 || rid > pe.rows[0x06]) return false;
        if (!pe.readBlob(pe.methodSigIndex(rid), sig)) return false;
    } else if (table == 0x0A) {
        uint32_t si = 0;
        if (!pe.memberRefSigIndex(rid, si)) return false;
        if (!pe.readBlob(si, sig)) return false;
    } else {
        return false;
    }
    return parseSig(sig, out);
}

// (popped, pushed) for every opcode the checker models.  Returns false for an
// opcode that is not modelled.
static bool ilStackEffect(uint16_t op, int& pops, int& pushes) {
    pops = 0;
    pushes = 0;
    if (op == 0x00 || op == 0x01) return true;                        // nop / break
    if (op >= 0x02 && op <= 0x05) { pushes = 1; return true; }         // ldarg.0-3
    if (op >= 0x06 && op <= 0x09) { pushes = 1; return true; }         // ldloc.0-3
    if (op >= 0x0A && op <= 0x0D) { pops = 1; return true; }           // stloc.0-3
    if (op == 0x0E || op == 0x0F) { pushes = 1; return true; }         // ldarg.s / ldarga.s
    if (op == 0x10) { pops = 1; return true; }                         // starg.s
    if (op == 0x11 || op == 0x12) { pushes = 1; return true; }         // ldloc.s / ldloca.s
    if (op == 0x13) { pops = 1; return true; }                         // stloc.s
    if (op == 0x14) { pushes = 1; return true; }                       // ldnull
    if (op >= 0x15 && op <= 0x23) { pushes = 1; return true; }         // ldc.*
    if (op == 0x25) { pops = 1; pushes = 2; return true; }             // dup
    if (op == 0x26) { pops = 1; return true; }                         // pop
    if (op == 0x27) { pops = 1; return true; }                         // jmp
    if (op == 0x2A) return true;                                       // ret
    if (op == 0x2B || op == 0x38 || op == 0xDD || op == 0xDE) return true;  // br / leave
    if (op == 0x2C || op == 0x2D || op == 0x39 || op == 0x3A) { pops = 1; return true; }
    if ((op >= 0x2E && op <= 0x37) || (op >= 0x3B && op <= 0x44)) { pops = 2; return true; }
    if (op == 0x45) { pops = 1; return true; }                         // switch
    if (op >= 0x46 && op <= 0x4E) { pops = 1; pushes = 1; return true; }  // ldind.*
    if (op >= 0x4F && op <= 0x54) { pops = 2; return true; }           // stind.*
    if ((op >= 0x58 && op <= 0x65) || (op >= 0xD6 && op <= 0xDB)) {
        pops = 2; pushes = 1; return true;                             // arithmetic
    }
    if ((op >= 0x66 && op <= 0x6C) || op == 0x76) { pops = 1; pushes = 1; return true; }
    if (op == 0x70) { pops = 2; return true; }                         // cpobj
    if (op == 0x71) { pops = 1; pushes = 1; return true; }             // ldobj
    if (op == 0x72) { pushes = 1; return true; }                       // ldstr
    if (op == 0x74 || op == 0x75) { pops = 1; pushes = 1; return true; }  // castclass / isinst
    if (op == 0x79 || op == 0x8C || op == 0xA5) { pops = 1; pushes = 1; return true; }
    if (op == 0x7A) { pops = 1; return true; }                         // throw
    if (op == 0x7B || op == 0x7C) { pops = 1; pushes = 1; return true; }  // ldfld / ldflda
    if (op == 0x7D) { pops = 2; return true; }                         // stfld
    if (op == 0x7E || op == 0x7F) { pushes = 1; return true; }         // ldsfld / ldsflda
    if (op == 0x80) { pops = 1; return true; }                         // stsfld
    if (op == 0x81) { pops = 2; return true; }                         // stobj
    if (op >= 0x82 && op <= 0x8A) { pops = 1; pushes = 1; return true; }  // conv.ovf.*
    if (op == 0x8D) { pops = 1; pushes = 1; return true; }             // newarr
    if (op == 0x8E) { pops = 1; pushes = 1; return true; }             // ldlen
    if (op == 0x8F) { pops = 2; pushes = 1; return true; }             // ldelema
    if (op >= 0x90 && op <= 0x9A) { pops = 2; pushes = 1; return true; }  // ldelem.*
    if (op >= 0x9B && op <= 0xA2) { pops = 3; return true; }           // stelem.*
    if (op == 0xA3) { pops = 2; pushes = 1; return true; }             // ldelem
    if (op == 0xA4) { pops = 3; return true; }                         // stelem
    if (op >= 0xB3 && op <= 0xBA) { pops = 1; pushes = 1; return true; }  // conv.ovf.*.un
    if (op == 0xC2) { pops = 1; pushes = 1; return true; }             // refanyval
    if (op == 0xC3) { pops = 1; pushes = 1; return true; }             // ckfinite
    if (op == 0xC6) { pops = 1; pushes = 1; return true; }             // mkrefany
    if (op == 0xD0) { pushes = 1; return true; }                       // ldtoken
    if (op >= 0xD1 && op <= 0xD5) { pops = 1; pushes = 1; return true; }
    if (op == 0xDC) return true;                                       // endfinally
    if (op == 0xE0) { pops = 1; pushes = 1; return true; }             // conv.u
    if (op >= 0xFE01 && op <= 0xFE05) { pops = 2; pushes = 1; return true; }
    if (op == 0xFE06) { pushes = 1; return true; }                     // ldftn
    if (op == 0xFE07) { pops = 1; pushes = 1; return true; }           // ldvirtftn
    if (op == 0xFE09 || op == 0xFE0A || op == 0xFE0C || op == 0xFE0D) { pushes = 1; return true; }
    if (op == 0xFE0B || op == 0xFE0E) { pops = 1; return true; }
    if (op == 0xFE0F) { pops = 1; pushes = 1; return true; }           // localloc
    if (op == 0xFE11) return true;                                     // endfilter
    if (op == 0xFE12 || op == 0xFE13 || op == 0xFE14 || op == 0xFE16 ||
        op == 0xFE19 || op == 0xFE1E) return true;                     // prefixes
    if (op == 0xFE15) { pops = 1; return true; }                       // initobj
    if (op == 0xFE17 || op == 0xFE18) { pops = 3; return true; }       // cpblk / initblk
    if (op == 0xFE1A) return true;                                     // rethrow
    if (op == 0xFE1C) { pushes = 1; return true; }                     // sizeof
    if (op == 0xFE1D) { pops = 1; pushes = 1; return true; }           // refanytype
    return false;
}

// Verify one method body.  Returns false and fills <err> on the first problem.
static bool verifyMethodIl(const PEImage& pe, const Bytes& il, const CallSig& selfSig,
                           const std::vector<uint32_t>& strictCalls, std::string& err) {
    std::vector<IlInstr> ops;
    if (!disassemble(il, ops, err)) return false;
    if (ops.empty()) { err = "empty method body"; return false; }
    std::map<size_t, size_t> index;
    for (size_t i = 0; i < ops.size(); ++i) index[ops[i].off] = i;

    struct State {
        long depth = 0;
        std::vector<uint32_t> types;
    };
    std::map<size_t, State> seen;
    seen[0] = State{0, {}};
    std::vector<size_t> work{0};

    while (!work.empty()) {
        size_t i = work.back();
        work.pop_back();
        const IlInstr& in = ops[i];
        State st = seen[in.off];
        long d = st.depth;
        std::vector<uint32_t> stack = st.types;
        std::vector<size_t> succ;

        auto popN = [&](long n) -> bool {
            if ((long)stack.size() < n) return false;
            stack.resize(stack.size() - (size_t)n);
            return true;
        };
        auto push = [&](uint32_t t) { stack.push_back(t); };

        if (in.op == 0x2A) {  // ret
            if (d != 0) {
                err = "the stack is not empty at ret IL_" + hx((uint32_t)in.off) +
                      " (depth " + std::to_string(d) + ")";
                return false;
            }
            continue;
        }
        if (in.op == 0x7A || in.op == 0xFE1A || in.op == 0xDC || in.op == 0xFE11 ||
            in.op == 0x27) {
            continue;  // throw / rethrow / endfinally / endfilter / jmp
        }

        if (in.op == 0x28 || in.op == 0x6F || in.op == 0x73) {  // call / callvirt / newobj
            CallSig cs;
            if (!resolveCallSig(pe, in.operand, cs)) {
                err = "cannot resolve the signature of call " + hx8(in.operand) +
                      " at IL_" + hx((uint32_t)in.off);
                return false;
            }
            long slots = (long)cs.paramCount + ((in.op != 0x73 && cs.hasThis) ? 1 : 0);
            if ((long)stack.size() < slots) {
                err = "not enough arguments for call " + hx8(in.operand) +
                      " at IL_" + hx((uint32_t)in.off);
                return false;
            }
            bool strict = std::find(strictCalls.begin(), strictCalls.end(), in.operand) !=
                          strictCalls.end();
            long first = (long)stack.size() - slots;
            long argBase = first + ((in.op != 0x73 && cs.hasThis) ? 1 : 0);
            for (long k = 0; strict && k < (long)cs.paramCount; ++k) {
                uint32_t want = cs.paramTypes[(size_t)k];
                uint32_t got = stack[(size_t)(argBase + k)];
                if (want && got != want) {
                    err = "argument " + std::to_string(k + 1) + " of call " + hx8(in.operand) +
                          " at IL_" + hx((uint32_t)in.off) + " has type " + hx8(got) +
                          " but the callee declares " + hx8(want);
                    return false;
                }
            }
            popN(slots);
            if (in.op == 0x73 || cs.returnsValue) push(0);
            succ.push_back(in.off + in.size);
        } else {
            int pops = 0, pushes = 0;
            if (!ilStackEffect(in.op, pops, pushes)) {
                err = "the checker does not model opcode " + hx((uint32_t)in.op) +
                      " at IL_" + hx((uint32_t)in.off);
                return false;
            }
            if (!popN(pops)) {
                err = "stack underflow at IL_" + hx((uint32_t)in.off);
                return false;
            }
            for (int k = 0; k < pushes; ++k) push(0);
            if (in.op == 0x74 || in.op == 0x75) {
                if (!stack.empty()) stack.back() = in.operand;  // cast fixes the type
            }
            if (in.op == 0x03 || in.op == 0x04 || in.op == 0x05) {
                size_t k = (size_t)(in.op - 0x03);
                stack.back() = k < selfSig.paramTypes.size() ? selfSig.paramTypes[k] : 0;
            }
            if (in.op == 0x02) stack.back() = 0;  // this
            if (in.op == 0x45) {                  // switch
                uint32_t n = in.operand;
                for (uint32_t k = 0; k < n; ++k) {
                    int32_t rel = rdi32(il, (size_t)(in.off + 5 + 4 * k));
                    succ.push_back((size_t)((long)(in.off + 5 + 4 * (size_t)n) + rel));
                }
                succ.push_back(in.off + in.size);
            } else if (in.op == 0xDD || in.op == 0xDE) {  // leave clears the stack
                succ.push_back(ilBranchTarget(in));
            } else if (ilIsBranch(in.op)) {
                succ.push_back(ilBranchTarget(in));
                if (ilIsCondBranch(in.op)) succ.push_back(in.off + in.size);
            } else {
                succ.push_back(in.off + in.size);
            }
        }

        bool clearing = (in.op == 0xDD || in.op == 0xDE);
        for (size_t target : succ) {
            auto it = index.find(target);
            if (it == index.end()) {
                err = "branch target IL_" + hx((uint32_t)target) +
                      " is not an instruction boundary (from IL_" + hx((uint32_t)in.off) + ")";
                return false;
            }
            long nd = clearing ? 0 : (long)stack.size();
            auto prev = seen.find(target);
            if (prev == seen.end() || prev->second.depth != nd) {
                State ns;
                ns.depth = nd;
                ns.types = clearing ? std::vector<uint32_t>() : stack;
                seen[target] = ns;
                work.push_back(it->second);
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Stage 3: restore "click a modpack -> download it straight into the game
// folder".
//
// Upstream PCL 2.99 rewired the version list of the resource detail page from
// the modpack installer (Install_Click) to the generic "save the file wherever
// the user wants" handler (Save_Click).  Install_Click is still present and
// still downloads into <MC folder>\versions\<name>\原始整合包.mrpack before
// handing the file to ModModpack.ModpackInstall, but nothing references it any
// more, so a modpack only ends up in the Downloads folder and has to be
// dragged back into PCL.
//
// The patch rebuilds Save_Click: modpack versions are forwarded to
// Install_Click, every other resource kind keeps the original behaviour.  All
// token / value lookups are done by name or by shape - nothing is hardcoded.
// ---------------------------------------------------------------------------

// Everything the Save_Click patch needs, resolved by name or from metadata -
// never from the byte layout of the original method.  That is what makes the
// patch survive a recompiled binary: only the *semantic* anchors are used.
struct SaveClickInfo {
    uint32_t listItemType = 0;        // PCL.MyListItem
    uint32_t parentStr = 0;           // "Parent"
    uint32_t tagStr = 0;              // "Tag"
    uint32_t lateGetRef = 0;          // NewLateBinding.LateGet
    uint32_t objArrayType = 0;        // System.Object (for newarr)
    uint32_t resourceVersionType = 0; // PCL.ResourceVersion
    uint32_t resourceTypeField = 0;   // PCL.ResourceVersion.ResourceType
    uint32_t installClick = 0;        // PCL.PageDownloadResourceDetail.Install_Click
    uint32_t installParamType = 0;    // declared type of its first parameter
    uint32_t modpackValue = 0;        // numeric value of ResourceType.ModPack
    uint32_t workerLambda = 0;        // the save worker (ldftn in the original body)
    uint32_t selfRid = 0;             // MethodDef row of Save_Click itself
};

// The textual description of every resource kind is a literal inside the save
// worker; the modpack one is "整合包".  The worker switches on
// (ResourceType - 1), so the numeric value of the modpack member equals the
// index of the switch case that reaches that literal, plus one.
static uint32_t deriveModpackValue(const PEImage& pe, const MethodInfo& worker,
                                   uint32_t modpackToken) {
    BodyInfo wb = pe.bodyOf(worker);
    Bytes il(pe.data.begin() + (long)wb.codeOff,
             pe.data.begin() + (long)(wb.codeOff + wb.codeSize));
    std::vector<IlInstr> ops;
    std::string derr;
    if (!disassemble(il, ops, derr))
        fail("Save_Click: the save worker does not decode: " + derr);

    // Several switches may exist in the worker; the one we want operates on
    // (ResourceType - 1) and one of its cases uses the modpack literal.
    for (size_t i = 3; i < ops.size(); ++i) {
        const IlInstr& sw = ops[i];
        if (sw.op != 0x45) continue;
        const IlInstr& s1 = ops[i - 3];
        const IlInstr& s2 = ops[i - 2];
        const IlInstr& s3 = ops[i - 1];
        bool one = (s2.op == 0x17) || (s2.op == 0x1F && s2.operand == 1) ||
                   (s2.op == 0x20 && s2.operand == 1);
        if (!(s1.op >= 0x06 && s1.op <= 0x09) || !one || s3.op != 0x59) continue;

        uint32_t n = sw.operand;
        if (n == 0 || n > 64) continue;
        uint32_t base = (uint32_t)(sw.off + 5 + 4 * n);
        for (uint32_t k = 0; k < n; ++k) {
            int32_t rel = rdi32(il, (size_t)(sw.off + 5 + 4 * k));
            long target = (long)base + rel;
            if (target < 0 || (size_t)target >= il.size()) continue;
            // a case body starts with "ldloc.0" and is followed by the description
            for (long p = target; p < (long)il.size() && p < target + 8; ++p) {
                if (il[(size_t)p] != 0x72) continue;
                if (rd32(il, (size_t)p + 1) == modpackToken) return k + 1;
                break;
            }
        }
    }
    fail("Save_Click: could not derive the numeric value of the modpack resource type");
    return 0;
}

// Numeric value of an enum literal, read from the Constant table - the same
// information the compiler emitted.  Returns 0 when it cannot be determined
// (for example when the enum lives in another assembly), so callers can treat
// it as "no independent confirmation".
static uint32_t deriveEnumValue(const PEImage& pe, uint32_t fieldToken,
                                const std::string& member) {
    if ((fieldToken >> 24) != 0x04) return 0;
    uint32_t rid = fieldToken & 0xFFFFFF;
    if (rid == 0 || rid > pe.rows[0x04]) return 0;
    const FieldInfo& f = pe.fields[(size_t)(rid - 1)];
    Bytes sig;
    if (!pe.readBlob(f.sigIdx, sig)) return 0;
    if (sig.size() < 2 || sig[0] != 0x06) return 0;  // FIELD <type>
    size_t i = 1;
    uint32_t typeToken = 0;
    if (!readSigType(sig, i, typeToken)) return 0;
    if ((typeToken >> 24) != 0x02) return 0;         // the enum has to be a TypeDef
    uint32_t typeRid = typeToken & 0xFFFFFF;
    if (typeRid == 0 || typeRid > pe.types.size()) return 0;

    int mi = pe.findField((int)typeRid - 1, member);
    if (mi < 0) return 0;
    uint32_t memberRid = pe.fields[(size_t)mi].rid;

    size_t start = 0;
    uint32_t rs = 0;
    if (!pe.tableInfo(0x0B, start, rs)) return 0;
    uint32_t psz = pe.codedSize(2, {0x04, 0x08, 0x17});  // HasConstant
    for (uint32_t r = 1; r <= pe.rows[0x0B]; ++r) {
        size_t o = start + (size_t)(r - 1) * rs;
        uint8_t type = pe.data[o];
        uint32_t parent = pe.readIndex(o + 2, psz);
        if ((parent & 3) != 0) continue;               // not a field
        if ((parent >> 2) != memberRid) continue;
        uint32_t blobIdx = pe.readIndex(o + 2 + psz, pe.blobSizeIdx);
        Bytes b;
        if (!pe.readBlob(blobIdx, b)) return 0;
        if (type == 0x08 && b.size() >= 4) return rd32(b, 0);  // I4
        if (type == 0x07 && b.size() >= 2) return rd16(b, 0);  // U2
        if (type == 0x05 && b.size() >= 1) return b[0];        // U1
        return 0;
    }
    return 0;
}

// Resolve the Save_Click patch inputs by name and by shape.
static SaveClickInfo resolveSaveClickTokens(const PEImage& pe, const MethodInfo& save,
                                            const MethodInfo& install,
                                            uint32_t resourceTypeField, const Bytes& code) {
    SaveClickInfo s;
    s.selfRid = save.rid;
    s.resourceTypeField = resourceTypeField;
    s.installClick = methodToken(install);

    int listItem = pe.findType("PCL.MyListItem");
    if (listItem < 0) fail("Save_Click: type not found: PCL.MyListItem");
    s.listItemType = 0x02000000u | pe.types[(size_t)listItem].rid;

    int version = pe.findType("PCL.ResourceVersion");
    if (version < 0) fail("Save_Click: type not found: PCL.ResourceVersion");
    s.resourceVersionType = 0x02000000u | pe.types[(size_t)version].rid;

    s.objArrayType = pe.findTypeRef("System.Object");
    if (s.objArrayType == 0) fail("Save_Click: System.Object was not found");

    s.lateGetRef =
        pe.findMemberRef("Microsoft.VisualBasic.CompilerServices.NewLateBinding", "LateGet");
    if (s.lateGetRef == 0) fail("Save_Click: NewLateBinding.LateGet was not found");

    s.parentStr = pe.findUsToken(utf16le({0x50, 0x61, 0x72, 0x65, 0x6E, 0x74})); // "Parent"
    s.tagStr = pe.findUsToken(utf16le({0x54, 0x61, 0x67}));                       // "Tag"
    if (s.parentStr == 0) fail("Save_Click: the \"Parent\" literal was not found");
    if (s.tagStr == 0) fail("Save_Click: the \"Tag\" literal was not found");

    // The save worker is the only ldftn target in the original body.  It is
    // needed to derive the numeric value of the modpack resource type.
    std::vector<IlInstr> ops;
    if (!disassemble(code, ops)) fail("Save_Click: the original body does not decode");
    uint32_t worker = 0;
    for (const IlInstr& in : ops) {
        if (in.op != 0xFE06) continue;
        if (worker) fail("Save_Click: the original body contains more than one ldftn");
        worker = in.operand;
    }
    if (!worker) fail("Save_Click: the save worker (ldftn) was not found");
    s.workerLambda = worker;

    // Install_Click's first parameter is a concrete class, so the owner has to
    // be cast to exactly that type before the call.  Both signatures are read
    // from the metadata and cross checked.
    Bytes installSig, saveSig;
    CallSig installInfo, saveInfo;
    if (!pe.readBlob(pe.methodSigIndex(install.rid), installSig) ||
        !parseSig(installSig, installInfo))
        fail("Save_Click: cannot read the signature of Install_Click");
    if (!pe.readBlob(pe.methodSigIndex(save.rid), saveSig) || !parseSig(saveSig, saveInfo))
        fail("Save_Click: cannot read the signature of Save_Click");
    if (installInfo.paramCount != 2 || saveInfo.paramCount != 2)
        fail("Save_Click: unexpected parameter count");
    if (installInfo.paramTypes[1] != saveInfo.paramTypes[1])
        fail("Save_Click: Install_Click and Save_Click disagree on the event argument type");
    if (installInfo.paramTypes[0] == 0 || installInfo.paramTypes[0] == 0x1C)
        fail("Save_Click: the first parameter of Install_Click is not a class type");
    s.installParamType = installInfo.paramTypes[0];

    std::cout << "  Save_Click tokens:\n"
              << "    MyListItem         " << hx8(s.listItemType) << "\n"
              << "    ResourceVersion    " << hx8(s.resourceVersionType) << "\n"
              << "    ResourceType       " << hx8(s.resourceTypeField) << "\n"
              << "    LateGet            " << hx8(s.lateGetRef) << "\n"
              << "    System.Object      " << hx8(s.objArrayType) << "\n"
              << "    \"Parent\" / \"Tag\"   " << hx8(s.parentStr) << " / " << hx8(s.tagStr) << "\n"
              << "    save worker        " << hx8(s.workerLambda) << "\n"
              << "    Install_Click      " << hx8(s.installClick)
              << " (first parameter " << hx8(s.installParamType) << ")\n";
    return s;
}

// Rebuild Save_Click: the routing prologue is synthesized from the resolved
// tokens, the original body is appended verbatim, so the "save the file"
// behaviour stays byte for byte what it was.
static Bytes buildSaveClickBody(const PEImage& pe, const BodyInfo& body, const SaveClickInfo& s,
                                uint32_t& newCodeSize) {
    if (body.hasSections)
        fail("Save_Click: the original body has an exception table; this patch needs an update");
    Bytes il;
    auto b = [&](uint8_t v) { il.push_back(v); };
    auto i32 = [&](uint32_t v) {
        b((uint8_t)(v & 0xFF)); b((uint8_t)((v >> 8) & 0xFF));
        b((uint8_t)((v >> 16) & 0xFF)); b((uint8_t)((v >> 24) & 0xFF));
    };

    // owner = If(sender Is MyListItem, sender, LateGet(sender, "Parent"))
    auto emitOwner = [&]() {
        b(0x03);                                        // ldarg.1 (sender)
        b(0x75); i32(s.listItemType);                   // isinst MyListItem
        b(0x2D);                                        // brtrue.s -> have
        size_t brTrue = il.size();
        b(0x00);
        b(0x03); b(0x14);                               // ldarg.1 / ldnull
        b(0x72); i32(s.parentStr);                      // ldstr "Parent"
        b(0x16);                                        // ldc.i4.0
        b(0x8D); i32(s.objArrayType);                   // newarr Object
        b(0x14); b(0x14); b(0x14);                      // ldnull x3
        b(0x28); i32(s.lateGetRef);                     // call LateGet
        b(0x2B);                                        // br.s -> join
        size_t brJoin = il.size();
        b(0x00);
        size_t have = il.size();
        b(0x03);                                        // ldarg.1
        size_t join = il.size();
        il[brTrue] = (uint8_t)(int8_t)((long)have - (long)(brTrue + 1));
        il[brJoin] = (uint8_t)(int8_t)((long)join - (long)(brJoin + 1));
    };

    emitOwner();                                        // -> [owner]
    b(0x14);                                            // ldnull
    b(0x72); i32(s.tagStr);                             // ldstr "Tag"
    b(0x16);                                            // ldc.i4.0
    b(0x8D); i32(s.objArrayType);                       // newarr Object
    b(0x14); b(0x14); b(0x14);                          // ldnull x3
    b(0x28); i32(s.lateGetRef);                         // call LateGet
    b(0x74); i32(s.resourceVersionType);                // castclass ResourceVersion
    b(0x7B); i32(s.resourceTypeField);                  // ldfld ResourceType
    if (s.modpackValue <= 8) b((uint8_t)(0x16 + s.modpackValue));
    else { b(0x20); i32(s.modpackValue); }
    b(0x33);                                            // bne.un.s -> notPack
    size_t bne = il.size();
    b(0x00);

    b(0x02);                                            // ldarg.0 (this)
    emitOwner();                                        // -> [this, owner]
    b(0x74); i32(s.listItemType);                       // castclass MyListItem
    if (s.installParamType != s.listItemType) {
        b(0x74); i32(s.installParamType);               // widen to the declared type
    }
    b(0x04);                                            // ldarg.2 (e)
    b(0x28); i32(s.installClick);                       // call Install_Click
    b(0x2A);                                            // ret
    size_t notPack = il.size();
    il[bne] = (uint8_t)(int8_t)((long)notPack - (long)(bne + 1));
    // the jump has to land exactly on the first instruction of the original
    // body - an off by one would silently skip the whole "save the file" logic
    if ((size_t)((long)(bne + 1) + (int8_t)il[bne]) != notPack || notPack != il.size())
        fail("Save_Click: internal error - the jump into the original body is misaligned");

    il.insert(il.end(), pe.data.begin() + (long)body.codeOff,
              pe.data.begin() + (long)(body.codeOff + body.codeSize));
    newCodeSize = (uint32_t)il.size();

    Bytes out;
    for (int i = 0; i < 12; ++i) out.push_back(pe.data[body.bodyOff + i]);
    wr32(out, 4, newCodeSize);
    out[2] = 0x10; out[3] = 0x00;  // MaxStack = 16 (an upper bound only)
    out.insert(out.end(), il.begin(), il.end());

    // The rebuilt body has to pass the very same checks the original passed.
    {
        CallSig selfSig;
        Bytes sSig;
        if (!pe.readBlob(pe.methodSigIndex(s.selfRid), sSig) || !parseSig(sSig, selfSig))
            fail("Save_Click: cannot read the signature of Save_Click");
        std::string err;
        if (!verifyMethodIl(pe, il, selfSig, {s.installClick}, err))
            fail("Save_Click: the rebuilt method does not verify: " + err);
    }
    return out;
}

// A patched Save_Click is one that calls Install_Click.  The original never
// does (the installer was orphaned), so this is a semantic marker rather than
// a byte pattern.
static bool isSaveClickPatched(const Bytes& code, uint32_t installToken) {
    std::vector<IlInstr> ops;
    if (!disassemble(code, ops)) return false;
    for (const IlInstr& in : ops)
        if (in.op == 0x28 && in.operand == installToken) return true;
    return false;
}

// A section that carries relocated method bodies.  The tool uses the section
// with the highest raw offset (PCL's .reloc) so the file can simply grow.
struct Carrier {
    size_t index = 0;
    size_t cursor = 0;  // offset inside the section of the next free slot
    uint32_t virtualSize = 0;
    uint32_t rawSize = 0;
};

static Carrier openCarrier(const PEImage& pe) {
    Carrier c;
    bool have = false;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        if (!have || (uint64_t)pe.sections[i].rawPtr > (uint64_t)pe.sections[c.index].rawPtr) {
            c.index = i;
            have = true;
        }
    }
    if (!have) fail("no PE sections");
    const Section& s = pe.sections[c.index];
    if ((uint64_t)s.rawPtr + s.rawSize != pe.data.size())
        fail("last section does not end at file end; refusing to extend (overlay or unusual layout)");
    c.cursor = alignUp(s.virtualSize, 4);
    c.virtualSize = s.virtualSize;
    c.rawSize = s.rawSize;
    return c;
}

// Place one method body into the carrier and return its new RVA / file offset.
static void placeInCarrier(const PEImage& pe, Carrier& c, const Bytes& body,
                           uint32_t& newRva, size_t& fileOff) {
    const Section& s = pe.sections[c.index];
    size_t at = alignUp(c.cursor, 4);
    newRva = s.virtualAddress + (uint32_t)at;
    fileOff = (size_t)s.rawPtr + at;
    c.cursor = at + body.size();
    uint32_t need = (uint32_t)(at + alignUp(body.size(), 0x400));
    if (need > c.virtualSize) c.virtualSize = need;
    c.rawSize = (uint32_t)alignUp(c.virtualSize, pe.fileAlignment);
    if (c.rawSize < at + body.size()) fail("internal: raw section size too small");
}

// Analysis of the original ModpackInstall body.  Everything is derived from
// the instruction stream: where the restriction stub sits, where the finally
// handler behind it starts, and which local the loader-type switch reads.
struct ModpackLayout {
    size_t stub = 0;            // offset of the "ldstr" of the restriction stub
    size_t stubLength = 0;      // ldstr + newobj + throw
    size_t finally = 0;         // offset of the finally handler
    size_t finallyLength = 0;
    long switchLocal = -1;
    uint32_t switchArity = 0;
    Bytes switchLoad;           // the instruction that loads the loader type
};

static const IlInstr* instrAt(const std::vector<IlInstr>& ops, size_t off) {
    for (const IlInstr& in : ops)
        if (in.off == off) return &in;
    return nullptr;
}

static ModpackLayout analyseModpackInstall(const Bytes& il) {
    std::vector<IlInstr> ops;
    std::string err;
    if (!disassemble(il, ops, err))
        fail("ModpackInstall: the body does not decode: " + err);

    ModpackLayout L;
    long stub = -1;
    for (size_t i = 0; i + 2 < ops.size(); ++i) {
        if (ops[i].op != 0x72 || ops[i + 1].op != 0x73 || ops[i + 2].op != 0x7A) continue;
        if (stub >= 0) fail("ModpackInstall: more than one restriction stub (ldstr/newobj/throw)");
        stub = (long)ops[i].off;
        L.stubLength = ops[i].size + ops[i + 1].size + ops[i + 2].size;
    }
    if (stub < 0)
        fail("ModpackInstall: the restriction stub (ldstr/newobj/throw) was not found");
    L.stub = (size_t)stub;
    L.finally = L.stub + L.stubLength;

    // the finally handler that follows the stub:
    //   ldloc.N / brfalse.s / ldloc.N / callvirt / endfinally
    const IlInstr* a = instrAt(ops, L.finally);
    if (!a || a->op < 0x06 || a->op > 0x09)
        fail("ModpackInstall: the finally handler was not found behind the stub");
    const IlInstr* b = instrAt(ops, a->off + a->size);
    if (!b || b->op != 0x2C)
        fail("ModpackInstall: the finally handler does not start with ldloc / brfalse");
    const IlInstr* c = instrAt(ops, b->off + b->size);
    if (!c || c->op != a->op)
        fail("ModpackInstall: the finally handler does not reload the same local");
    const IlInstr* d = instrAt(ops, c->off + c->size);
    if (!d || (d->op != 0x6F && d->op != 0x28))
        fail("ModpackInstall: the finally handler does not release the local");
    const IlInstr* e = instrAt(ops, d->off + d->size);
    if (!e || e->op != 0xDC)
        fail("ModpackInstall: the finally handler does not end with endfinally");
    L.finallyLength = (e->off + e->size) - L.finally;

    // The body detects the modpack format and stores it in a local; the
    // original code then either installs it or (upstream) throws.  The local
    // and the number of formats are derived from the constants assigned to it,
    // e.g. "ldc.i4.s 9 / stloc.s 4" means the format enum has 10 members.
    std::map<long, long> maxConstant;  // local -> highest constant stored into it
    for (size_t i = 1; i < ops.size(); ++i) {
        long local = -1;
        const IlInstr& st = ops[i];
        if (st.op >= 0x0A && st.op <= 0x0D) local = (long)st.op - 0x0A;
        else if (st.op == 0x13) local = (long)st.operand;
        else if (st.op == 0xFE0E) local = (long)st.operand;
        if (local < 0) continue;
        const IlInstr& c = ops[i - 1];
        long v = 0;
        bool isConst = true;
        if (c.op >= 0x15 && c.op <= 0x1E) v = (long)c.op - 0x16;   // ldc.i4.m1 .. ldc.i4.8
        else if (c.op == 0x1F) v = (int8_t)(uint8_t)c.operand;
        else if (c.op == 0x20) v = (int32_t)c.operand;
        else isConst = false;
        if (!isConst) continue;
        auto it = maxConstant.find(local);
        if (it == maxConstant.end() || v > it->second) maxConstant[local] = v;
    }
    long best = -1, bestMax = -1;
    for (const auto& kv : maxConstant) {
        if (kv.second > bestMax) { bestMax = kv.second; best = kv.first; }
        else if (kv.second == bestMax) best = -1;  // ambiguous
    }
    if (best < 0) fail("ModpackInstall: the modpack format local was not found");
    if (bestMax < 4 || bestMax > 63)
        fail("ModpackInstall: implausible number of modpack formats (" +
             std::to_string(bestMax + 1) + ")");
    L.switchArity = (uint32_t)(bestMax + 1);
    L.switchLocal = best;
    L.switchLoad.clear();
    if (best <= 3) {
        L.switchLoad.push_back((uint8_t)(0x06 + best));            // ldloc.0-3
    } else {
        L.switchLoad.push_back(0x11);                              // ldloc.s
        L.switchLoad.push_back((uint8_t)best);
    }
    return L;
}

// Rebuild the body: the untouched prefix, a switch that dispatches to the
// installer for the selected mod loader, the original finally handler and a
// small epilogue.  The dispatch replaces the restriction stub in place, so the
// branch targets of the original prefix stay valid.
static Bytes buildModpackCode(const PEImage& pe, const BodyInfo& body, const InstallerTokens& t,
                              const ModpackLayout& L, uint32_t& newCodeSize,
                              uint32_t& finallyStartOut, uint32_t& finallyLenOut) {
    const Bytes& code = pe.data;
    const uint32_t D = (uint32_t)L.stub;

    Bytes dispatch;
    std::vector<size_t> switchFix;
    std::vector<size_t> leaveFix;
    size_t brFix = 0;

    auto b = [&](uint8_t v) { dispatch.push_back(v); };
    auto i32 = [&](uint32_t v) {
        b((uint8_t)(v & 0xFF));
        b((uint8_t)((v >> 8) & 0xFF));
        b((uint8_t)((v >> 16) & 0xFF));
        b((uint8_t)((v >> 24) & 0xFF));
    };
    auto call = [&](std::initializer_list<uint8_t> loads, uint32_t token) {
        for (uint8_t x : loads) b(x);
        b(0x28); i32(token);
        b(0x0A); // stloc.0
        b(0xDD); // leave
        leaveFix.push_back(dispatch.size());
        i32(0);
    };

    dispatch.insert(dispatch.end(), L.switchLoad.begin(), L.switchLoad.end());
    b(0x45); i32(L.switchArity);                       // switch
    size_t switchEnd = dispatch.size() + 4 * L.switchArity;
    for (uint32_t i = 0; i < L.switchArity; ++i) {     // jump table
        switchFix.push_back(dispatch.size());
        i32(0);
    }
    b(0x38); brFix = dispatch.size(); i32(0);          // br default

    // The case order is the mod-loader order used by the installer methods:
    // 0 CurseForge, 1 HMCL, 2 MMC, 3 MCBBS, 4 Modrinth, last LauncherPack,
    // everything else falls back to the generic (Compress) installer.
    size_t caseCurseForge = D + dispatch.size();
    call({0x02, 0x07, 0x08, 0x03, 0x04}, t.curseForge);
    size_t caseHmcl = D + dispatch.size();
    call({0x02, 0x07, 0x08}, t.hmcl);
    size_t caseMmc = D + dispatch.size();
    call({0x02, 0x07, 0x08}, t.mmc);
    size_t caseMcbbs = D + dispatch.size();
    call({0x02, 0x07, 0x08, 0x03}, t.mcbbs);
    size_t caseModrinth = D + dispatch.size();
    call({0x02, 0x07, 0x08, 0x03, 0x04}, t.modrinth);
    size_t caseLauncherPack = D + dispatch.size();
    call({0x02, 0x07, 0x08}, t.launcherPack);
    size_t caseDefault = D + dispatch.size();
    call({0x02, 0x07}, t.compress);

    size_t finallyStart = D + dispatch.size();
    size_t epilogue = finallyStart + L.finallyLength;
    finallyStartOut = (uint32_t)finallyStart;
    finallyLenOut = (uint32_t)L.finallyLength;

    std::vector<size_t> targets(L.switchArity, caseDefault);
    targets[0] = caseCurseForge;
    targets[1] = caseHmcl;
    targets[2] = caseMmc;
    targets[3] = caseMcbbs;
    targets[4] = caseModrinth;
    targets[L.switchArity - 1] = caseLauncherPack;
    for (uint32_t i = 0; i < L.switchArity; ++i) {
        int32_t rel = (int32_t)targets[i] - (int32_t)(D + switchEnd);
        wr32(dispatch, switchFix[i], (uint32_t)rel);
    }
    {
        int32_t rel = (int32_t)caseDefault - (int32_t)(D + brFix + 4);
        wr32(dispatch, brFix, (uint32_t)rel);
    }
    for (size_t p : leaveFix) {
        int32_t rel = (int32_t)epilogue - (int32_t)(D + p + 4);
        wr32(dispatch, p, (uint32_t)rel);
    }

    newCodeSize = (uint32_t)(L.stub + dispatch.size() + L.finallyLength + 2);

    Bytes out;
    out.reserve((size_t)12 + newCodeSize);
    for (int i = 0; i < 12; ++i) out.push_back(code[body.bodyOff + i]);
    wr32(out, 4, newCodeSize);
    for (size_t i = 0; i < L.stub; ++i) out.push_back(code[body.codeOff + i]);
    out.insert(out.end(), dispatch.begin(), dispatch.end());
    for (size_t i = L.finally; i < L.finally + L.finallyLength; ++i)
        out.push_back(code[body.codeOff + i]);
    out.push_back(0x06); // ldloc.0
    out.push_back(0x2A); // ret

    // Self check: the rebuilt IL has to decode and every branch has to land on
    // an instruction boundary (or on the very end of the code).
    {
        Bytes ilOnly(out.begin() + 12, out.end());
        std::vector<IlInstr> ops;
        std::string derr;
        if (!disassemble(ilOnly, ops, derr))
            fail("ModpackInstall: the rebuilt body does not decode: " + derr);
        std::map<size_t, int> starts;
        for (const IlInstr& in : ops) starts[in.off] = 1;
        for (const IlInstr& in : ops) {
            if (!ilIsBranch(in.op)) continue;
            std::vector<size_t> targets;
            if (in.op == 0x45) {
                uint32_t n = in.operand;
                size_t base = in.off + 5 + (size_t)4 * n;
                for (uint32_t k = 0; k < n; ++k) {
                    int32_t rel = rdi32(ilOnly, (size_t)(in.off + 5 + 4 * k));
                    targets.push_back((size_t)((long)base + rel));
                }
            } else {
                targets.push_back(ilBranchTarget(in));
            }
            for (size_t t : targets) {
                if (t == ilOnly.size()) continue;  // fall out of the method
                if (!starts.count(t))
                    fail("ModpackInstall: internal error - branch target IL_" +
                         hx((uint32_t)t) + " is not an instruction boundary");
            }
        }
    }
    return out;
}

struct ModpackPatch {
    Bytes methodBody;      // header + code + EH
    uint32_t newRva = 0;
    size_t bodyFileOff = 0;
    uint32_t newCodeSize = 0;
    uint32_t finallyStart = 0;
    uint32_t finallyLength = 0;
    size_t stubStart = 0;
    long switchLocal = -1;
    uint32_t switchArity = 0;
    size_t carrierIndex = 0;
    uint32_t newVirtualSize = 0;
    uint32_t newRawSize = 0;
};

static ModpackPatch buildModpackBody(PEImage& pe, const BodyInfo& body,
                                     const InstallerTokens& inst, Carrier& carrier) {
    Bytes il(pe.data.begin() + (long)body.codeOff,
              pe.data.begin() + (long)(body.codeOff + body.codeSize));
    ModpackLayout layout = analyseModpackInstall(il);

    uint32_t newCodeSize = 0, finallyStart = 0, finallyLength = 0;
    Bytes method = buildModpackCode(pe, body, inst, layout, newCodeSize, finallyStart,
                                    finallyLength);

    // The exception table follows the IL, aligned to 4.  The clause that covers
    // the restriction stub is the outer finally; it has to be moved to the
    // relocated handler.
    size_t ehOff = alignUp(body.codeOff + body.codeSize, 4);
    uint8_t kind = pe.data[ehOff];
    if (!(kind & 0x40)) fail("ModpackInstall: expected a fat exception table");
    uint32_t dataSize = (uint32_t)pe.data[ehOff + 1] |
                        ((uint32_t)pe.data[ehOff + 2] << 8) |
                        ((uint32_t)pe.data[ehOff + 3] << 16);
    if (dataSize < 4 || (dataSize - 4) % 24 != 0)
        fail("ModpackInstall: bad exception table size " + hx(dataSize));
    Bytes eh(pe.data.begin() + (long)ehOff, pe.data.begin() + (long)(ehOff + dataSize));
    bool found = false;
    for (size_t o = 4; o + 24 <= eh.size(); o += 24) {
        uint32_t flags = rd32(eh, o);
        int32_t tryOff = rdi32(eh, o + 4);
        int32_t tryLen = rdi32(eh, o + 8);
        int32_t handlerOff = rdi32(eh, o + 12);
        int32_t handlerLen = rdi32(eh, o + 16);
        if (tryLen <= 0) continue;
        if (!((int32_t)layout.stub >= tryOff && (int32_t)layout.stub < tryOff + tryLen)) continue;
        if (found) continue;  // keep the innermost clause
        if ((flags & 0x2) == 0)   // COR_ILEXCEPTION_CLAUSE_FINALLY
            fail("ModpackInstall: the clause covering the restriction stub is not a finally (flags=" +
                 hx(flags) + ")");
        if ((size_t)handlerOff != layout.finally || (size_t)handlerLen != layout.finallyLength)
            fail("ModpackInstall: the clause covering the restriction stub does not point at "
                 "the handler behind it");
        wr32(eh, o + 8, (uint32_t)((int32_t)finallyStart - tryOff));   // try length
        wr32(eh, o + 12, finallyStart);                                // handler offset
        wr32(eh, o + 16, finallyLength);                               // handler length
        found = true;
    }
    if (!found) fail("ModpackInstall: the finally clause covering the stub was not found");

    // Pad the IL to a 4-byte boundary before the exception table.
    uint32_t pad = (uint32_t)((4 - (newCodeSize & 3)) & 3);
    method.insert(method.end(), pad, 0x00);
    method.insert(method.end(), eh.begin(), eh.end());

    ModpackPatch p;
    p.methodBody = std::move(method);
    p.newCodeSize = newCodeSize;
    p.finallyStart = finallyStart;
    p.finallyLength = finallyLength;
    p.stubStart = layout.stub;
    p.switchLocal = layout.switchLocal;
    p.switchArity = layout.switchArity;

    p.carrierIndex = carrier.index;
    placeInCarrier(pe, carrier, p.methodBody, p.newRva, p.bodyFileOff);
    p.newVirtualSize = carrier.virtualSize;
    p.newRawSize = carrier.rawSize;
    return p;
}

struct SaveClickPatch {
    Bytes methodBody;      // header + code
    uint32_t newRva = 0;
    size_t bodyFileOff = 0;
    uint32_t newCodeSize = 0;
    size_t carrierIndex = 0;
    uint32_t newVirtualSize = 0;
    uint32_t newRawSize = 0;
};

static SaveClickPatch buildSaveClickPatch(const PEImage& pe, const BodyInfo& body,
                                          const SaveClickInfo& info, Carrier& carrier) {
    SaveClickPatch p;
    uint32_t newCodeSize = 0;
    p.methodBody = buildSaveClickBody(pe, body, info, newCodeSize);
    p.newCodeSize = newCodeSize;
    p.carrierIndex = carrier.index;
    placeInCarrier(pe, carrier, p.methodBody, p.newRva, p.bodyFileOff);
    p.newVirtualSize = carrier.virtualSize;
    p.newRawSize = carrier.rawSize;
    return p;
}

static void printReport(const PEImage& pe,
                        const BodyInfo& loaderBody, const BodyInfo& modpackBody,
                        const FieldInfo& dlField, const MethodInfo& loader,
                        const MethodInfo& modpack) {
    std::cout << "PE: sections=" << pe.numSections
              << " sectionAlign=" << hx(pe.sectionAlignment)
              << " fileAlign=" << hx(pe.fileAlignment)
              << " imageSize=" << hx(pe.sizeOfImage) << "\n";
    std::cout << "Metadata: typeDef=" << pe.types.size()
              << " methodDef=" << pe.methods.size()
              << " field=" << pe.fields.size() << "\n";
    std::cout << "Types:\n"
              << "  PageDownloadInstall token=" << hx8(0x02000000u | pe.types[loader.typeIndex].rid) << "\n"
              << "  ModModpack          token=" << hx8(0x02000000u | pe.types[modpack.typeIndex].rid) << "\n"
              << "  ModDownload         token=" << hx8(0x02000000u | pe.types[dlField.typeIndex].rid) << "\n";
    std::cout << "Methods:\n"
              << "  LoaderInit    token=" << hx8(methodToken(loader))
              << " rva=" << hx8(loader.rva) << " code=" << hx(loaderBody.codeSize) << "\n"
              << "  ModpackInstall token=" << hx8(methodToken(modpack))
              << " rva=" << hx8(modpack.rva) << " code=" << hx(modpackBody.codeSize) << "\n";
    std::cout << "Field:\n"
              << "  DlClientListLoader token=" << hx8(fieldToken(dlField))
              << " type=" << pe.types[dlField.typeIndex].ns << "." << pe.types[dlField.typeIndex].name << "\n";
    std::cout << "Sections:\n";
    for (const auto& s : pe.sections) {
        std::cout << "  " << s.name << " VA=" << hx(s.virtualAddress)
                  << " VS=" << hx(s.virtualSize)
                  << " RawPtr=" << hx(s.rawPtr)
                  << " RawSize=" << hx(s.rawSize)
                  << " Char=" << hx(s.characteristics) << "\n";
    }
}

// A patched ModpackInstall no longer contains the restriction stub and does
// contain the installer dispatch.
static bool isModpackPatched(const Bytes& code) {
    std::vector<IlInstr> ops;
    if (!disassemble(code, ops)) return false;
    bool stub = false;
    bool dispatch = false;
    for (size_t i = 0; i + 2 < ops.size(); ++i)
        if (ops[i].op == 0x72 && ops[i + 1].op == 0x73 && ops[i + 2].op == 0x7A) stub = true;
    for (const IlInstr& in : ops)
        if (in.op == 0x45) dispatch = true;
    if (!stub && !dispatch)
        fail("ModpackInstall: neither the original stub nor the patched dispatch was found");
    return !stub && dispatch;
}

static void writeFile(const std::string& path, const Bytes& b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) fail("cannot open output: " + path);
    f.write((const char*)b.data(), (std::streamsize)b.size());
    if (!f) fail("write failed: " + path);
}

static Bytes readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) fail("cannot open input: " + path);
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    if (n < 0) fail("cannot determine input size: " + path);
    f.seekg(0, std::ios::beg);
    Bytes b((size_t)n);
    f.read((char*)b.data(), n);
    if (!f) fail("read failed: " + path);
    return b;
}

static std::string deriveOutputPath(const std::string& in) {
    size_t slash = in.find_last_of("\\/");
    size_t dot = in.find_last_of('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash))
        dot = in.size();
    return in.substr(0, dot) + ".autopatched" + in.substr(dot);
}

static void usage(const char* exe) {
    std::cout
        << "PCLAutoPatch - automatic PCL download/modpack gate patcher\n"
        << "Usage:\n"
        << "  " << exe << " <input.exe> [output.exe] [--verify] [--force] [--verbose]\n\n"
        << "Default output: <input>.autopatched.exe\n"
        << "The input file is never modified. Existing output is refused unless --force.\n"
        << "  --verify   only report what was detected; write nothing\n"
        << "  --probe    analyse the input and print every derived anchor, write nothing\n"
        << "  --force    overwrite an existing output file\n"
        << "  --verbose  print the patch details\n"
        << "  --help     show this help\n";
}

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    try {
        std::string inPath, outPath;
        bool verifyOnly = false, force = false, verbose = false, probe = false;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--verify") verifyOnly = true;
            else if (a == "--probe") { verifyOnly = true; probe = true; }
            else if (a == "--force") force = true;
            else if (a == "--verbose" || a == "-v") verbose = true;
            else if (a == "--help" || a == "-h") { usage(argv[0]); return 0; }
            else if (!a.empty() && a[0] == '-') fail("unknown option: " + a);
            else if (inPath.empty()) inPath = a;
            else if (outPath.empty()) outPath = a;
            else fail("too many positional arguments");
        }
        if (inPath.empty()) { usage(argv[0]); return 2; }
        if (outPath.empty()) outPath = deriveOutputPath(inPath);
        if (canonicalPath(inPath) == canonicalPath(outPath))
            fail("output path must differ from input path; the input is never modified");

        Bytes data = readFile(inPath);
        PEImage pe(data);
        pe.readUsHeap();

        int loaderType = pe.findType("PCL.PageDownloadInstall");
        int modType = pe.findType("PCL.ModModpack");
        int dlType = pe.findType("PCL.ModDownload");
        if (loaderType < 0) fail("type not found: PCL.PageDownloadInstall");
        if (modType < 0) fail("type not found: PCL.ModModpack");
        if (dlType < 0) fail("type not found: PCL.ModDownload");

        int loaderIdx = pe.findMethod(loaderType, "LoaderInit");
        if (loaderIdx < 0) fail("method not found: PCL.PageDownloadInstall.LoaderInit");
        const MethodInfo& loader = pe.methods[loaderIdx];
        BodyInfo loaderBody = pe.bodyOf(loader);

        // ModpackInstall has a 0-arg hint stub and the 3-arg real body.
        int modpackIdx = -1;
        BodyInfo modpackBody;
        for (size_t i = 0; i < pe.methods.size(); ++i) {
            const MethodInfo& m = pe.methods[i];
            if (m.typeIndex != modType || m.name != "ModpackInstall") continue;
            BodyInfo b = pe.bodyOf(m);
            if (b.codeSize == 0x2EF || b.codeSize == 0x380) {
                if (modpackIdx >= 0) fail("multiple ModpackInstall bodies with expected size");
                modpackIdx = (int)i;
                modpackBody = b;
            }
        }
        if (modpackIdx < 0)
            fail("method not found: PCL.ModModpack.ModpackInstall(String,String,String) with expected body size");
        const MethodInfo& modpack = pe.methods[modpackIdx];

        int dlIdx = pe.findField(dlType, "DlClientListLoader");
        if (dlIdx < 0) fail("field not found: PCL.ModDownload.DlClientListLoader");
        const FieldInfo& dlField = pe.fields[dlIdx];

        // Stage 3: the resource detail page decides between "save the file
        // somewhere" and "download the modpack into the game folder".
        int detailType = pe.findType("PCL.PageDownloadResourceDetail");
        int versionType = pe.findType("PCL.ResourceVersion");
        if (detailType < 0) fail("type not found: PCL.PageDownloadResourceDetail");
        if (versionType < 0) fail("type not found: PCL.ResourceVersion");
        int saveIdx = pe.findMethod(detailType, "Save_Click");
        int installIdx = pe.findMethod(detailType, "Install_Click");
        if (saveIdx < 0) fail("method not found: PCL.PageDownloadResourceDetail.Save_Click");
        if (installIdx < 0) fail("method not found: PCL.PageDownloadResourceDetail.Install_Click");
        const MethodInfo& saveMethod = pe.methods[saveIdx];
        const MethodInfo& installMethod = pe.methods[installIdx];
        BodyInfo saveBody = pe.bodyOf(saveMethod);
        int typeFieldIdx = pe.findField(versionType, "ResourceType");
        if (typeFieldIdx < 0) fail("field not found: PCL.ResourceVersion.ResourceType");
        const FieldInfo& typeField = pe.fields[typeFieldIdx];

        std::cout << "Input: " << inPath << " (" << data.size() << " bytes)\n";
        printReport(pe, loaderBody, modpackBody, dlField, loader, modpack);

        // ------------------------------------------------------------------
        // "Already patched?" is answered semantically, not by byte offsets:
        //   LoaderInit    - the body equals the body this tool would produce
        //   ModpackInstall- the restriction stub is gone and a dispatch is there
        //   Save_Click    - the body calls Install_Click
        // ------------------------------------------------------------------
        Bytes loaderCode(pe.data.begin() + (long)loaderBody.codeOff,
                         pe.data.begin() + (long)(loaderBody.codeOff + loaderBody.codeSize));
        LoaderTokens lt = extractLoaderTokens(pe, loaderType, loaderCode, fieldToken(dlField));
        Bytes newLoaderCode = buildLoaderPatch(lt);
        bool loaderPatched =
            loaderCode.size() >= newLoaderCode.size() &&
            std::equal(newLoaderCode.begin(), newLoaderCode.end(), loaderCode.begin());

        bool modpackPatched = false;
        {
            const Bytes code(pe.data.begin() + (long)modpackBody.codeOff,
                             pe.data.begin() + (long)(modpackBody.codeOff + modpackBody.codeSize));
            modpackPatched = isModpackPatched(code);
        }
        bool savePatched = false;
        {
            const Bytes code(pe.data.begin() + (long)saveBody.codeOff,
                             pe.data.begin() + (long)(saveBody.codeOff + saveBody.codeSize));
            savePatched = isSaveClickPatched(code, methodToken(installMethod));
        }
        std::cout << "State: LoaderInit=" << (loaderPatched ? "already patched" : "original")
                  << ", ModpackInstall=" << (modpackPatched ? "already patched" : "original")
                  << ", Save_Click=" << (savePatched ? "already patched" : "original") << "\n";

        if (verifyOnly && !probe) {
            std::cout << "Verify-only: no output written.\n";
            return 0;
        }
        if (loaderPatched && modpackPatched && savePatched) {
            if (!force && std::ifstream(outPath, std::ios::binary).good())
                fail("output exists; use --force to overwrite: " + outPath);
            writeFile(outPath, data);
            std::cout << "All gates are already patched; copied input to:\n  " << outPath << "\n";
            return 0;
        }

        if (!probe && !force && std::ifstream(outPath, std::ios::binary).good())
            fail("output exists; use --force to overwrite: " + outPath);

        InstallerTokens inst;
        ModpackPatch mp;
        SaveClickPatch sc;
        Carrier carrier = openCarrier(pe);
        if (!modpackPatched) {
            inst = resolveInstallers(pe, modType);
            mp = buildModpackBody(pe, modpackBody, inst, carrier);
            std::cout << "ModpackInstall patch: stub=IL_" << hx((uint32_t)mp.stubStart)
                      << " finally=IL_" << hx(mp.finallyStart) << "+" << hx(mp.finallyLength)
                      << " formatLocal=" << mp.switchLocal << " formats=" << mp.switchArity
                      << " code=" << hx(mp.newCodeSize)
                      << " body=" << mp.methodBody.size()
                      << " newRVA=" << hx8(mp.newRva)
                      << " fileOff=" << hx((uint32_t)mp.bodyFileOff) << "\n";
        } else {
            std::cout << "ModpackInstall is already patched; skipping relocation.\n";
        }

        SaveClickInfo sci;
        if (!savePatched) {
            Bytes saveCode(pe.data.begin() + (long)saveBody.codeOff,
                           pe.data.begin() + (long)(saveBody.codeOff + saveBody.codeSize));
            sci = resolveSaveClickTokens(pe, saveMethod, installMethod, fieldToken(typeField), saveCode);

            // The method the patch is based on has to be verifiable, otherwise
            // the checker cannot vouch for the rebuilt body either.
            {
                CallSig selfSig;
                Bytes sSig;
                if (!pe.readBlob(pe.methodSigIndex(saveMethod.rid), sSig) ||
                    !parseSig(sSig, selfSig))
                    fail("Save_Click: cannot read the signature of Save_Click");
                std::string err;
                if (!verifyMethodIl(pe, saveCode, selfSig, {}, err))
                    fail("Save_Click: the original method does not verify: " + err);
            }

            // The save worker tags every resource kind with a literal; the
            // modpack one is "???".  Its position in the worker's switch
            // gives the numeric value of the modpack member of the resource
            // type enum.  The enum literal in the metadata is an independent
            // second source and the two have to agree.
            uint32_t modpackToken = pe.findUsToken(utf16le({0x6574, 0x5408, 0x5305}));
            if (modpackToken == 0)
                fail("Save_Click: the modpack description literal was not found");
            int workerIdx = -1;
            for (size_t i = 0; i < pe.methods.size(); ++i) {
                if (pe.methods[i].rid == (sci.workerLambda & 0xFFFFFF)) {
                    workerIdx = (int)i;
                    break;
                }
            }
            if (workerIdx < 0) fail("Save_Click: the save worker method was not found");
            uint32_t bySwitch =
                deriveModpackValue(pe, pe.methods[(size_t)workerIdx], modpackToken);
            uint32_t byEnum = deriveEnumValue(pe, fieldToken(typeField), "ModPack");
            if (byEnum != 0 && byEnum != bySwitch)
                fail("Save_Click: the switch table and the enum literal disagree on the "
                     "modpack resource type (" + std::to_string(bySwitch) + " vs " +
                     std::to_string(byEnum) + ")");
            sci.modpackValue = bySwitch;
            std::cout << "Save_Click patch: modpack resource type = " << sci.modpackValue
                      << " (from the save worker's switch table";
            if (byEnum) std::cout << ", confirmed by the enum literal";
            else std::cout << "; the enum itself lives outside this file";
            std::cout << "), install target = " << hx8(sci.installClick) << "\n";
            sc = buildSaveClickPatch(pe, saveBody, sci, carrier);
            std::cout << "Save_Click patch: code=" << hx(sc.newCodeSize)
                      << " body=" << sc.methodBody.size()
                      << " newRVA=" << hx8(sc.newRva)
                      << " fileOff=" << hx((uint32_t)sc.bodyFileOff) << "\n";
        } else {
            std::cout << "Save_Click is already patched; skipping relocation.\n";
        }

        if (probe) {
            std::cout << "Probe: every anchor was derived from the metadata and the IL shape; "
                         "no output written.\n";
            return 0;
        }

        Bytes out = data;
        if (!loaderPatched) {
            // The new body is written in place, so it must not overrun the
            // original body (that would corrupt the next method).
            if (newLoaderCode.size() > loaderBody.codeSize)
                fail("LoaderInit: the rebuilt body (" + std::to_string(newLoaderCode.size()) +
                     " bytes) does not fit into the original body (" +
                     std::to_string(loaderBody.codeSize) + " bytes)");
            for (size_t i = 0; i < newLoaderCode.size(); ++i)
                out[loaderBody.codeOff + i] = newLoaderCode[i];
            for (size_t i = newLoaderCode.size(); i < loaderBody.codeSize; ++i)
                out[loaderBody.codeOff + i] = 0x00;
            if (!loaderBody.fat) fail("LoaderInit: tiny header, unexpected");
            wr32(out, loaderBody.bodyOff + 4, (uint32_t)newLoaderCode.size());
        }

        if (!modpackPatched || !savePatched) {
            // Both relocated bodies live in the same carrier section.
            size_t carrierIndex = !modpackPatched ? mp.carrierIndex : sc.carrierIndex;
            Section& s = pe.sections[carrierIndex];
            uint32_t newVirtualSize = carrier.virtualSize;
            uint32_t newRawSize = carrier.rawSize;
            size_t newFileSize = (size_t)s.rawPtr + newRawSize;
            if (newFileSize < out.size()) newFileSize = out.size();
            out.resize(newFileSize, 0x00);
            if (!modpackPatched) {
                for (size_t i = 0; i < mp.methodBody.size(); ++i)
                    out[mp.bodyFileOff + i] = mp.methodBody[i];
                wr32(out, modpack.rowOff, mp.newRva);
            }
            if (!savePatched) {
                for (size_t i = 0; i < sc.methodBody.size(); ++i)
                    out[sc.bodyFileOff + i] = sc.methodBody[i];
                wr32(out, saveMethod.rowOff, sc.newRva);
            }
            wr32(out, s.headerOff + 8, newVirtualSize);
            wr32(out, s.headerOff + 16, newRawSize);
            wr32(out, s.headerOff + 36, 0x60000020);
            uint32_t imageEnd = 0;
            if (!modpackPatched)
                imageEnd = (uint32_t)alignUp((size_t)mp.newRva + mp.methodBody.size(),
                                             pe.sectionAlignment);
            if (!savePatched) {
                uint32_t e = (uint32_t)alignUp((size_t)sc.newRva + sc.methodBody.size(),
                                               pe.sectionAlignment);
                if (e > imageEnd) imageEnd = e;
            }
            if (imageEnd > pe.sizeOfImage) wr32(out, pe.optOff + 56, imageEnd);
        }

        // Verify by reparsing the output bytes.
        PEImage v(out);
        int vLoaderType = v.findType("PCL.PageDownloadInstall");
        int vModType = v.findType("PCL.ModModpack");
        if (vLoaderType < 0 || vModType < 0) fail("verify: types missing in output");
        int vLoaderIdx = v.findMethod(vLoaderType, "LoaderInit");
        if (vLoaderIdx < 0) fail("verify: LoaderInit missing in output");
        BodyInfo vLoader = v.bodyOf(v.methods[vLoaderIdx]);
        if (!loaderPatched) {
            Bytes vCode(v.data.begin() + vLoader.codeOff,
                        v.data.begin() + vLoader.codeOff + vLoader.codeSize);
            if (vCode != newLoaderCode)
                fail("verify: LoaderInit bytes do not match the patch");
        }

        int vModIdx = -1;
        BodyInfo vMod;
        for (size_t i = 0; i < v.methods.size(); ++i) {
            const MethodInfo& m = v.methods[i];
            if (m.typeIndex != vModType || m.name != "ModpackInstall") continue;
            BodyInfo b = v.bodyOf(m);
            if (modpackPatched ? isModpackPatched(Bytes(v.data.begin() + (long)b.codeOff,
                                                     v.data.begin() + (long)(b.codeOff + b.codeSize)))
                               : b.codeSize == mp.newCodeSize) {
                vModIdx = (int)i;
                vMod = b;
                break;
            }
        }
        if (vModIdx < 0) fail("verify: patched ModpackInstall body not found");
        if (!modpackPatched) {
            if (vMod.codeSize != mp.newCodeSize) fail("verify: ModpackInstall code size mismatch");
            Bytes vCode(v.data.begin() + vMod.codeOff,
                        v.data.begin() + vMod.codeOff + vMod.codeSize);
            if (!isModpackPatched(vCode)) fail("verify: ModpackInstall switch pattern missing");
            if (rd32(v.data, v.methods[vModIdx].rowOff) != mp.newRva)
                fail("verify: MethodDef RVA was not updated");
            uint32_t vEH = (uint32_t)alignUp(vMod.codeOff + vMod.codeSize, 4);
            uint32_t vDataSize = (uint32_t)v.data[vEH + 1] |
                                 ((uint32_t)v.data[vEH + 2] << 8) |
                                 ((uint32_t)v.data[vEH + 3] << 16);
            bool vFound = false;
            for (size_t o = vEH + 4; o + 24 <= vEH + vDataSize; o += 24) {
                if ((int32_t)rd32(v.data, o + 4) == 39) {
                    if ((int32_t)rd32(v.data, o + 12) != (int32_t)mp.finallyStart)
                        fail("verify: finally handler offset mismatch");
                    vFound = true;
                }
            }
            if (!vFound) fail("verify: finally clause missing in output");
        }

        if (!savePatched) {
            int vDetailType = v.findType("PCL.PageDownloadResourceDetail");
            if (vDetailType < 0) fail("verify: PageDownloadResourceDetail missing in output");
            int vSaveIdx = v.findMethod(vDetailType, "Save_Click");
            if (vSaveIdx < 0) fail("verify: Save_Click missing in output");
            BodyInfo vSave = v.bodyOf(v.methods[vSaveIdx]);
            if (vSave.codeSize != sc.newCodeSize) fail("verify: Save_Click code size mismatch");
            Bytes vCode(v.data.begin() + vSave.codeOff,
                        v.data.begin() + vSave.codeOff + vSave.codeSize);
            if (!isSaveClickPatched(vCode, sci.installClick))
                fail("verify: Save_Click does not call Install_Click");
            if (rd32(v.data, v.methods[vSaveIdx].rowOff) != sc.newRva)
                fail("verify: Save_Click MethodDef RVA was not updated");
            // the patched body must call Install_Click exactly once
            bool sawInstall = false;
            for (size_t i = 0; i + 4 < vCode.size(); ++i) {
                if (vCode[i] == 0x28 && rd32(vCode, i + 1) == sci.installClick) sawInstall = true;
            }
            if (!sawInstall) fail("verify: Save_Click does not call Install_Click");
        }

        writeFile(outPath, out);
        std::cout << "OK: wrote " << outPath << " (" << out.size() << " bytes)\n";
        if (verbose) {
            std::cout << "Patch details:\n";
            if (!loaderPatched) {
                std::cout << "  LoaderInit code size " << hx(loaderBody.codeSize)
                          << " -> " << hx((uint32_t)newLoaderCode.size()) << "\n";
                std::cout << "  LoaderInit IL:";
                for (uint8_t b : newLoaderCode) std::cout << ' ' << hx(b);
                std::cout << "\n";
            }
            if (!modpackPatched) {
                const Section& cs = pe.sections[mp.carrierIndex];
                std::cout << "  ModpackInstall code size " << hx(modpackBody.codeSize)
                          << " -> " << hx(mp.newCodeSize) << "\n";
                std::cout << "  ModpackInstall new RVA " << hx8(mp.newRva)
                          << ", file offset " << hx((uint32_t)mp.bodyFileOff) << "\n";
                std::cout << "  ModpackInstall outer finally handler at IL offset "
                          << hx(mp.finallyStart) << "\n";
                std::cout << "  MethodDef RVA updated at file offset "
                          << hx((uint32_t)modpack.rowOff) << "\n";
                std::cout << "  Carrier section " << cs.name
                          << ": virtual size " << hx(cs.virtualSize)
                          << " -> " << hx(mp.newVirtualSize)
                          << ", raw size " << hx(cs.rawSize)
                          << " -> " << hx(mp.newRawSize) << "\n";
            }
            if (!savePatched) {
                std::cout << "  Save_Click code size " << hx(saveBody.codeSize)
                          << " -> " << hx(sc.newCodeSize) << "\n";
                std::cout << "  Save_Click modpack resource type value = " << sci.modpackValue << "\n";
                std::cout << "  Save_Click new RVA " << hx8(sc.newRva)
                          << ", file offset " << hx((uint32_t)sc.bodyFileOff) << "\n";
                std::cout << "  Save_Click MethodDef RVA updated at file offset "
                          << hx((uint32_t)saveMethod.rowOff) << "\n";
            }
            std::cout << "  Record the output hash with: Get-FileHash -Algorithm SHA256 <file>\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
