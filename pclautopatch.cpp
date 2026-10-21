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
        } else {
            fail("unsupported method header flags for " + m.name);
        }
        b.codeOff = b.bodyOff + b.headerSize;
        if (b.codeOff + b.codeSize > data.size()) fail("method body out of bounds: " + m.name);
        return b;
    }
};

struct LoaderTokens {
    uint32_t controlInit = 0;
    uint32_t loadMinecraft = 0;
    uint32_t panLoad = 0;
    uint32_t panAllBack = 0;
    uint32_t lambda = 0;
    uint32_t actionCtor = 0;
    uint32_t pageLoaderInit = 0;
    uint32_t dlLoaderField = 0;
};

static uint32_t methodToken(const MethodInfo& m) { return 0x06000000u | m.rid; }
static uint32_t fieldToken(const FieldInfo& f) { return 0x04000000u | f.rid; }

static LoaderTokens extractLoaderTokens(const Bytes& code, const FieldInfo& dlField) {
    if (code.size() != 0x5E) fail("LoaderInit: expected 0x5E bytes, got " + hx((uint32_t)code.size()));
    if (!(code[0] == 0x02 && code[1] == 0x28)) fail("LoaderInit: ControlInit pattern mismatch");
    if (!(code[8] == 0x6F && code[0x0E] == 0x6F && code[0x14] == 0x6F))
        fail("LoaderInit: getter pattern mismatch");
    if (!(code[0x19] == 0x14 && code[0x1A] == 0x72))
        fail("LoaderInit: dummy loader string pattern mismatch");
    if (!(code[0x4B] == 0xFE && code[0x4C] == 0x06))
        fail("LoaderInit: ldftn lambda pattern mismatch");
    if (!(code[0x51] == 0x73 && code[0x58] == 0x28 && code[0x5D] == 0x2A))
        fail("LoaderInit: epilogue pattern mismatch");

    LoaderTokens t;
    t.controlInit = rd32(code, 2);
    t.loadMinecraft = rd32(code, 9);
    t.panLoad = rd32(code, 0x0F);
    t.panAllBack = rd32(code, 0x15);
    t.lambda = rd32(code, 0x4D);
    t.actionCtor = rd32(code, 0x52);
    t.pageLoaderInit = rd32(code, 0x59);
    t.dlLoaderField = fieldToken(dlField);

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
    b(0x17);
    b(0x28); i32(t.pageLoaderInit);
    b(0x2A);
    if (c.size() != 51) fail("internal: LoaderInit patch is not 51 bytes");
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

static Bytes buildModpackCode(const PEImage& pe,
                              const BodyInfo& body, const InstallerTokens& t,
                              uint32_t& newCodeSize, uint32_t& finallyStartOut) {
    const uint32_t D = 0x2DA;
    if (body.codeSize != 0x2EF) fail("ModpackInstall: expected code size 0x2EF, got " + hx(body.codeSize));
    const Bytes& code = pe.data;
    if (!(code[body.codeOff + 0x2DA] == 0x72 &&
          code[body.codeOff + 0x2DF] == 0x73 &&
          code[body.codeOff + 0x2E4] == 0x7A))
        fail("ModpackInstall: restriction stub pattern mismatch at IL_02DA");
    if (!(code[body.codeOff + 0x2E5] == 0x07 &&
          code[body.codeOff + 0x2E6] == 0x2C &&
          code[body.codeOff + 0x2E8] == 0x07 &&
          code[body.codeOff + 0x2E9] == 0x6F &&
          code[body.codeOff + 0x2EE] == 0xDC))
        fail("ModpackInstall: finally block pattern mismatch at IL_02E5");

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

    b(0x11); b(0x04);          // ldloc.s 4
    b(0x45); i32(10);          // switch
    size_t switchEnd = dispatch.size() + 40;
    for (int i = 0; i < 10; ++i) {
        switchFix.push_back(dispatch.size());
        i32(0);
    }
    b(0x38); brFix = dispatch.size(); i32(0); // br default

    size_t case0 = D + dispatch.size(); call({0x02, 0x07, 0x08, 0x03, 0x04}, t.curseForge);
    size_t case1 = D + dispatch.size(); call({0x02, 0x07, 0x08}, t.hmcl);
    size_t case2 = D + dispatch.size(); call({0x02, 0x07, 0x08}, t.mmc);
    size_t case3 = D + dispatch.size(); call({0x02, 0x07, 0x08, 0x03}, t.mcbbs);
    size_t case4 = D + dispatch.size(); call({0x02, 0x07, 0x08, 0x03, 0x04}, t.modrinth);
    size_t case9 = D + dispatch.size(); call({0x02, 0x07, 0x08}, t.launcherPack);
    size_t def   = D + dispatch.size(); call({0x02, 0x07}, t.compress);

    size_t finallyStart = D + dispatch.size();
    size_t epilogue = finallyStart + 10;
    finallyStartOut = (uint32_t)finallyStart;

    size_t targets[10] = {case0, case1, case2, case3, case4, def, def, def, def, case9};
    for (int i = 0; i < 10; ++i) {
        int32_t rel = (int32_t)targets[i] - (int32_t)(D + switchEnd);
        wr32(dispatch, switchFix[i], (uint32_t)rel);
    }
    {
        int32_t rel = (int32_t)def - (int32_t)(D + brFix + 4);
        wr32(dispatch, brFix, (uint32_t)rel);
    }
    for (size_t p : leaveFix) {
        int32_t rel = (int32_t)epilogue - (int32_t)(D + p + 4);
        wr32(dispatch, p, (uint32_t)rel);
    }

    newCodeSize = 0x2DA + (uint32_t)dispatch.size() + 10 + 2;
    if (newCodeSize != 0x380)
        fail("ModpackInstall: rebuilt code size is " + hx(newCodeSize) + ", expected 0x380");

    Bytes out;
    out.reserve((size_t)12 + newCodeSize);
    const size_t prefix = 0x2DA;
    const size_t finallyOff = 0x2E5;
    const size_t finallyLen = 10;
    for (int i = 0; i < 12; ++i) out.push_back(code[body.bodyOff + i]);
    wr32(out, 4, newCodeSize);
    for (size_t i = 0; i < prefix; ++i) out.push_back(code[body.codeOff + i]);
    out.insert(out.end(), dispatch.begin(), dispatch.end());
    for (size_t i = 0; i < finallyLen; ++i) out.push_back(code[body.codeOff + finallyOff + i]);
    out.push_back(0x06); // ldloc.0
    out.push_back(0x2A); // ret
    return out;
}

struct ModpackPatch {
    Bytes methodBody;      // header + code + EH
    uint32_t newRva = 0;
    size_t bodyFileOff = 0;
    uint32_t newCodeSize = 0;
    uint32_t finallyStart = 0;
    size_t carrierIndex = 0;
    uint32_t newVirtualSize = 0;
    uint32_t newRawSize = 0;
};

static ModpackPatch buildModpackBody(PEImage& pe, const BodyInfo& body,
                                     const InstallerTokens& inst) {
    uint32_t newCodeSize = 0, finallyStart = 0;
    Bytes method = buildModpackCode(pe, body, inst, newCodeSize, finallyStart);

    // Exception table follows the IL, aligned to 4.
    size_t ehOff = alignUp(body.codeOff + body.codeSize, 4);
    uint8_t kind = pe.data[ehOff];
    if (!(kind & 0x40)) fail("ModpackInstall: expected a fat exception table");
    uint32_t dataSize = (uint32_t)pe.data[ehOff + 1] |
                        ((uint32_t)pe.data[ehOff + 2] << 8) |
                        ((uint32_t)pe.data[ehOff + 3] << 16);
    if (dataSize < 4 || (dataSize - 4) % 24 != 0)
        fail("ModpackInstall: bad exception table size " + hx(dataSize));
    Bytes eh(pe.data.begin() + ehOff, pe.data.begin() + ehOff + dataSize);
    bool found = false;
    for (size_t o = 4; o + 24 <= eh.size(); o += 24) {
        int32_t tryOff = rdi32(eh, o + 4);
        if (tryOff == 39) {
            wr32(eh, o + 8, finallyStart - 39); // try length
            wr32(eh, o + 12, finallyStart);     // handler offset
            wr32(eh, o + 16, 10);               // handler length
            found = true;
        }
    }
    if (!found) fail("ModpackInstall: outer finally clause (try offset 39) not found");

    // Pad the IL to a 4-byte boundary before the exception table.
    uint32_t pad = (uint32_t)((4 - (newCodeSize & 3)) & 3);
    method.insert(method.end(), pad, 0x00);
    method.insert(method.end(), eh.begin(), eh.end());

    ModpackPatch p;
    p.methodBody = std::move(method);
    p.newCodeSize = newCodeSize;
    p.finallyStart = finallyStart;

    // Use the last section in the raw file as the carrier. PCL's .reloc is last.
    size_t carrier = 0;
    bool haveCarrier = false;
    for (size_t i = 0; i < pe.sections.size(); ++i) {
        if (!haveCarrier ||
            (uint64_t)pe.sections[i].rawPtr > (uint64_t)pe.sections[carrier].rawPtr) {
            carrier = i;
            haveCarrier = true;
        }
    }
    if (!haveCarrier) fail("no PE sections");
    const Section& s = pe.sections[carrier];
    if ((uint64_t)s.rawPtr + s.rawSize != pe.data.size())
        fail("last section does not end at file end; refusing to extend (overlay or unusual layout)");
    size_t insertRel = alignUp(s.virtualSize, 4);
    p.carrierIndex = carrier;
    p.newRva = s.virtualAddress + (uint32_t)insertRel;
    p.bodyFileOff = (size_t)s.rawPtr + insertRel;
    p.newVirtualSize = (uint32_t)(insertRel + alignUp(p.methodBody.size(), 0x400));
    // SizeOfRawData must be a multiple of FileAlignment. Round the virtual
    // size up rather than the body end, matching the layout used by the
    // original manual patch (0x40C -> 0x600).
    p.newRawSize = (uint32_t)alignUp(p.newVirtualSize, pe.fileAlignment);
    if (p.newRawSize < insertRel + p.methodBody.size())
        fail("internal: raw section size too small");
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

static bool isLoaderPatched(const Bytes& code) {
    return code.size() == 51 && code[0] == 0x02 && code[1] == 0x28 &&
           code[0x19] == 0x14 && code[0x1A] == 0x7E && code[0x32] == 0x2A;
}

static bool isModpackPatched(const Bytes& code) {
    return code.size() == 0x380 && code[0x2DA] == 0x11 && code[0x2DB] == 0x04 &&
           code[0x2DC] == 0x45;
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
        << "  --force    overwrite an existing output file\n"
        << "  --verbose  print the patch details\n"
        << "  --help     show this help\n";
}

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    try {
        std::string inPath, outPath;
        bool verifyOnly = false, force = false, verbose = false;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--verify") verifyOnly = true;
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

        std::cout << "Input: " << inPath << " (" << data.size() << " bytes)\n";
        printReport(pe, loaderBody, modpackBody, dlField, loader, modpack);

        bool loaderPatched = false;
        bool modpackPatched = false;
        {
            const Bytes code(pe.data.begin() + loaderBody.codeOff,
                             pe.data.begin() + loaderBody.codeOff + loaderBody.codeSize);
            loaderPatched = isLoaderPatched(code);
        }
        {
            const Bytes code(pe.data.begin() + modpackBody.codeOff,
                             pe.data.begin() + modpackBody.codeOff + modpackBody.codeSize);
            modpackPatched = isModpackPatched(code);
        }
        std::cout << "State: LoaderInit=" << (loaderPatched ? "already patched" : "original")
                  << ", ModpackInstall=" << (modpackPatched ? "already patched" : "original") << "\n";

        if (verifyOnly) {
            std::cout << "Verify-only: no output written.\n";
            return 0;
        }
        if (loaderPatched && modpackPatched) {
            if (!force && std::ifstream(outPath, std::ios::binary).good())
                fail("output exists; use --force to overwrite: " + outPath);
            writeFile(outPath, data);
            std::cout << "Both gates are already patched; copied input to:\n  " << outPath << "\n";
            return 0;
        }

        if (!force && std::ifstream(outPath, std::ios::binary).good())
            fail("output exists; use --force to overwrite: " + outPath);

        // Extract loader tokens before modifying anything.
        Bytes loaderCode(pe.data.begin() + loaderBody.codeOff,
                         pe.data.begin() + loaderBody.codeOff + loaderBody.codeSize);
        LoaderTokens lt;
        if (!loaderPatched) {
            lt = extractLoaderTokens(loaderCode, dlField);
        } else {
            std::cout << "LoaderInit is already patched; skipping token extraction.\n";
        }

        InstallerTokens inst;
        ModpackPatch mp;
        if (!modpackPatched) {
            inst = resolveInstallers(pe, modType);
            mp = buildModpackBody(pe, modpackBody, inst);
            std::cout << "ModpackInstall patch: code=" << hx(mp.newCodeSize)
                      << " body=" << mp.methodBody.size()
                      << " newRVA=" << hx8(mp.newRva)
                      << " fileOff=" << hx((uint32_t)mp.bodyFileOff) << "\n";
        } else {
            std::cout << "ModpackInstall is already patched; skipping relocation.\n";
        }

        Bytes out = data;
        Bytes newLoaderCode;
        if (!loaderPatched) {
            newLoaderCode = buildLoaderPatch(lt);
            for (size_t i = 0; i < newLoaderCode.size(); ++i)
                out[loaderBody.codeOff + i] = newLoaderCode[i];
            for (size_t i = newLoaderCode.size(); i < loaderBody.codeSize; ++i)
                out[loaderBody.codeOff + i] = 0x00;
            if (!loaderBody.fat) fail("LoaderInit: tiny header, unexpected");
            wr32(out, loaderBody.bodyOff + 4, (uint32_t)newLoaderCode.size());
        }

        if (!modpackPatched) {
            Section& s = pe.sections[mp.carrierIndex];
            size_t newFileSize = (size_t)s.rawPtr + mp.newRawSize;
            if (newFileSize < out.size()) newFileSize = out.size();
            out.resize(newFileSize, 0x00);
            for (size_t i = 0; i < mp.methodBody.size(); ++i)
                out[mp.bodyFileOff + i] = mp.methodBody[i];
            wr32(out, s.headerOff + 8, mp.newVirtualSize);
            wr32(out, s.headerOff + 16, mp.newRawSize);
            wr32(out, s.headerOff + 36, 0x60000020);
            uint32_t imageEnd = (uint32_t)alignUp((size_t)mp.newRva + mp.methodBody.size(),
                                                  pe.sectionAlignment);
            if (imageEnd > pe.sizeOfImage) wr32(out, pe.optOff + 56, imageEnd);
            wr32(out, modpack.rowOff, mp.newRva);
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
            if (vCode.size() != 51 || vCode != newLoaderCode)
                fail("verify: LoaderInit bytes do not match the patch");
        }

        int vModIdx = -1;
        BodyInfo vMod;
        for (size_t i = 0; i < v.methods.size(); ++i) {
            const MethodInfo& m = v.methods[i];
            if (m.typeIndex != vModType || m.name != "ModpackInstall") continue;
            BodyInfo b = v.bodyOf(m);
            if (b.codeSize == (modpackPatched ? 0x380 : mp.newCodeSize)) {
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
            std::cout << "  Record the output hash with: Get-FileHash -Algorithm SHA256 <file>\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
