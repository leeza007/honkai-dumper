#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// Minimal IL2CPP type definitions used by the dumper logic
struct Il2CppClass;
struct Il2CppType;
struct FieldInfo;
struct Il2CppAssembly;
struct Il2CppDomain;
struct Il2CppImage;

struct MethodInfo {
    Il2CppClass* klass;
    const void* method_pointer;
    unsigned char _pad[0x20];
    unsigned short flags;
};

// Constants mirrored from src/il2cpp/constants.rs
constexpr int FIELD_ATTRIBUTE_FIELD_ACCESS_MASK = 0x0007;
constexpr int FIELD_ATTRIBUTE_PRIVATE = 0x0001;
constexpr int FIELD_ATTRIBUTE_FAM_AND_ASSEM = 0x0002;
constexpr int FIELD_ATTRIBUTE_ASSEMBLY = 0x0003;
constexpr int FIELD_ATTRIBUTE_FAMILY = 0x0004;
constexpr int FIELD_ATTRIBUTE_FAM_OR_ASSEM = 0x0005;
constexpr int FIELD_ATTRIBUTE_PUBLIC = 0x0006;
constexpr int FIELD_ATTRIBUTE_STATIC = 0x0010;
constexpr int FIELD_ATTRIBUTE_INIT_ONLY = 0x0020;
constexpr int FIELD_ATTRIBUTE_LITERAL = 0x0040;

constexpr int METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK = 0x0007;
constexpr int METHOD_ATTRIBUTE_PRIVATE = 0x0001;
constexpr int METHOD_ATTRIBUTE_ASSEM = 0x0003;
constexpr int METHOD_ATTRIBUTE_FAMILY = 0x0004;
constexpr int METHOD_ATTRIBUTE_FAM_OR_ASSEM = 0x0005;
constexpr int METHOD_ATTRIBUTE_PUBLIC = 0x0006;
constexpr int METHOD_ATTRIBUTE_STATIC = 0x0010;
constexpr int METHOD_ATTRIBUTE_FINAL = 0x0020;
constexpr int METHOD_ATTRIBUTE_VIRTUAL = 0x0040;
constexpr int METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK = 0x0100;
constexpr int METHOD_ATTRIBUTE_NEW_SLOT = 0x0100;
constexpr int METHOD_ATTRIBUTE_ABSTRACT = 0x0400;
constexpr int METHOD_ATTRIBUTE_PINVOKE_IMPL = 0x2000;
constexpr int METHOD_ATTRIBUTE_REUSE_SLOT = 0x0000;

constexpr int TYPE_ATTRIBUTE_VISIBILITY_MASK = 0x00000007;
constexpr int TYPE_ATTRIBUTE_PUBLIC = 0x00000001;
constexpr int TYPE_ATTRIBUTE_NESTED_PUBLIC = 0x00000002;
constexpr int TYPE_ATTRIBUTE_NESTED_PRIVATE = 0x00000003;
constexpr int TYPE_ATTRIBUTE_NESTED_FAMILY = 0x00000004;
constexpr int TYPE_ATTRIBUTE_NESTED_ASSEMBLY = 0x00000005;
constexpr int TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM = 0x00000006;
constexpr int TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM = 0x00000007;
constexpr int TYPE_ATTRIBUTE_INTERFACE = 0x00000020;
constexpr int TYPE_ATTRIBUTE_ABSTRACT = 0x00000080;
constexpr int TYPE_ATTRIBUTE_SEALED = 0x00000100;
constexpr int TYPE_ATTRIBUTE_SERIALIZABLE = 0x00002000;

constexpr int PARAM_ATTRIBUTE_IN = 0x0001;
constexpr int PARAM_ATTRIBUTE_OUT = 0x0002;

// Simple PE helper to compute module size
size_t GetModuleSize(HMODULE module) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(module) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    return nt->OptionalHeader.SizeOfImage;
}

struct Module {
    HMODULE handle{};
    size_t size{};

    static Module Load(const std::filesystem::path& path) {
        Module module{};
        module.handle = ::LoadLibraryA(path.string().c_str());
        if (!module.handle) {
            throw std::runtime_error("Failed to load module: " + path.string());
        }
        module.size = GetModuleSize(module.handle);
        return module;
    }
};

// Function pointer holder mirroring src/il2cpp/functions.rs
struct Il2CppFunctions {
    using AssemblyGetImage = Il2CppImage* (*)(const Il2CppAssembly*);
    using ClassGetFields = FieldInfo* (*)(const Il2CppClass*, const void* const*);
    using ClassGetInterfaces = Il2CppClass* (*)(const Il2CppClass*, const void* const*);
    using ClassGetMethods = MethodInfo* (*)(const Il2CppClass*, const void* const*);
    using ClassGetName = const char* (*)(const Il2CppClass*);
    using ClassGetNamespace = const char* (*)(const Il2CppClass*);
    using ClassGetParent = Il2CppClass* (*)(const Il2CppClass*);
    using ClassIsValueType = bool (*)(const Il2CppClass*);
    using ClassGetFlags = int (*)(const Il2CppClass*);
    using ClassFromType = Il2CppClass* (*)(const Il2CppType*);
    using ClassIsEnum = bool (*)(const Il2CppClass*);

    using DomainGet = Il2CppDomain* (*)();
    using DomainGetAssemblies = Il2CppAssembly* const* (*)(const Il2CppDomain*, const size_t*);

    using FieldGetFlags = int (*)(const FieldInfo*);
    using FieldGetName = const char* (*)(const FieldInfo*);
    using FieldGetOffset = size_t (*)(const FieldInfo*);
    using FieldGetType = Il2CppType* (*)(const FieldInfo*);

    using MethodGetReturnType = Il2CppType* (*)(const MethodInfo*);
    using MethodGetName = const char* (*)(const MethodInfo*);
    using MethodGetParamCount = uint32_t (*)(const MethodInfo*);
    using MethodGetParam = Il2CppType* (*)(const MethodInfo*, uint32_t);

    using TypeGetName = const char* (*)(const Il2CppType*);
    using TypeIsByRef = bool (*)(const Il2CppType*);
    using TypeGetAttrs = uint32_t (*)(const Il2CppType*);

    using ImageGetName = const char* (*)(const Il2CppImage*);
    using ImageGetClassCount = size_t (*)(const Il2CppImage*);
    using ImageGetClass = Il2CppClass* (*)(const Il2CppImage*, size_t);

    AssemblyGetImage il2cpp_assembly_get_image{};
    ClassGetFields il2cpp_class_get_fields{};
    ClassGetInterfaces il2cpp_class_get_interfaces{};
    ClassGetMethods il2cpp_class_get_methods{};
    ClassGetName il2cpp_class_get_name{};
    ClassGetNamespace il2cpp_class_get_namespace{};
    ClassGetParent il2cpp_class_get_parent{};
    ClassIsValueType il2cpp_class_is_valuetype{};
    ClassGetFlags il2cpp_class_get_flags{};
    ClassFromType il2cpp_class_from_type{};
    ClassIsEnum il2cpp_class_is_enum{};

    DomainGet il2cpp_domain_get{};
    DomainGetAssemblies il2cpp_domain_get_assemblies{};

    FieldGetFlags il2cpp_field_get_flags{};
    FieldGetName il2cpp_field_get_name{};
    FieldGetOffset il2cpp_field_get_offset{};
    FieldGetType il2cpp_field_get_type{};

    MethodGetReturnType il2cpp_method_get_return_type{};
    MethodGetName il2cpp_method_get_name{};
    MethodGetParamCount il2cpp_method_get_param_count{};
    MethodGetParam il2cpp_method_get_param{};

    TypeGetName il2cpp_type_get_name{};
    TypeIsByRef il2cpp_type_is_byref{};
    TypeGetAttrs il2cpp_type_get_attrs{};

    ImageGetName il2cpp_image_get_name{};
    ImageGetClassCount il2cpp_image_get_class_count{};
    ImageGetClass il2cpp_image_get_class{};

    explicit Il2CppFunctions(uintptr_t base) {
        auto funcs = reinterpret_cast<const void* const*>(base + 0x1efe7c8);

        auto index = [&](size_t idx) -> const void* {
            const void* addr = funcs[idx];
            return addr;
        };

        il2cpp_assembly_get_image = reinterpret_cast<AssemblyGetImage>(index(22));
        il2cpp_class_get_methods = reinterpret_cast<ClassGetMethods>(index(35));
        il2cpp_class_get_name = reinterpret_cast<ClassGetName>(index(37));
        il2cpp_class_get_namespace = reinterpret_cast<ClassGetNamespace>(index(39));
        il2cpp_domain_get = reinterpret_cast<DomainGet>(index(63));
        il2cpp_domain_get_assemblies = reinterpret_cast<DomainGetAssemblies>(index(65));
        il2cpp_method_get_name = reinterpret_cast<MethodGetName>(index(117));
        il2cpp_image_get_class_count = reinterpret_cast<ImageGetClassCount>(index(169));
        il2cpp_image_get_class = reinterpret_cast<ImageGetClass>(index(170));

        // Optional for the C# dumper
        il2cpp_class_get_fields = reinterpret_cast<ClassGetFields>(index(31));
        il2cpp_class_get_interfaces = reinterpret_cast<ClassGetInterfaces>(index(33));
        il2cpp_class_get_parent = reinterpret_cast<ClassGetParent>(index(40));
        il2cpp_class_is_valuetype = reinterpret_cast<ClassIsValueType>(index(43));
        il2cpp_class_get_flags = reinterpret_cast<ClassGetFlags>(index(45));
        il2cpp_class_from_type = reinterpret_cast<ClassFromType>(index(49));
        il2cpp_class_is_enum = reinterpret_cast<ClassIsEnum>(index(53));
        il2cpp_field_get_flags = reinterpret_cast<FieldGetFlags>(index(72));
        il2cpp_field_get_name = reinterpret_cast<FieldGetName>(index(73));
        il2cpp_field_get_offset = reinterpret_cast<FieldGetOffset>(index(75));
        il2cpp_field_get_type = reinterpret_cast<FieldGetType>(index(76));
        il2cpp_method_get_return_type = reinterpret_cast<MethodGetReturnType>(index(116));
        il2cpp_method_get_param_count = reinterpret_cast<MethodGetParamCount>(index(123));
        il2cpp_method_get_param = reinterpret_cast<MethodGetParam>(index(124));
        il2cpp_type_get_name = reinterpret_cast<TypeGetName>(index(161));
        il2cpp_type_is_byref = reinterpret_cast<TypeIsByRef>(index(162));
        il2cpp_type_get_attrs = reinterpret_cast<TypeGetAttrs>(index(163));
        il2cpp_image_get_name = reinterpret_cast<ImageGetName>(index(168));
    }
};

class Il2CppApi {
public:
    Module game_assembly;
    Module unity_player;
    Il2CppFunctions functions;

    explicit Il2CppApi(const std::filesystem::path& root)
        : game_assembly(Module::Load(root / "GameAssembly.dll")),
          unity_player(Module::Load(root / "UnityPlayer.dll")),
          functions(reinterpret_cast<uintptr_t>(unity_player.handle)) {}

    static std::optional<Il2CppApi> CreateFromLoadedModules() {
        char buffer[MAX_PATH] = {};
        HMODULE game = GetModuleHandleA("GameAssembly.dll");
        if (!game) {
            return std::nullopt;
        }
        if (!GetModuleFileNameA(game, buffer, MAX_PATH)) {
            return std::nullopt;
        }
        std::filesystem::path root(buffer);
        root = root.parent_path();
        try {
            return Il2CppApi(root);
        } catch (...) {
            return std::nullopt;
        }
    }

    Il2CppDomain* domain_get() const { return Expect(functions.il2cpp_domain_get, "il2cpp_domain_get")(); }

    Il2CppAssembly* const* domain_get_assemblies(const Il2CppDomain* domain, const size_t* size) const {
        return Expect(functions.il2cpp_domain_get_assemblies, "il2cpp_domain_get_assemblies")(domain, size);
    }

    Il2CppImage* assembly_get_image(const Il2CppAssembly* assembly) const {
        return Expect(functions.il2cpp_assembly_get_image, "il2cpp_assembly_get_image")(assembly);
    }

    Il2CppClass* image_get_class(const Il2CppImage* image, size_t index) const {
        return Expect(functions.il2cpp_image_get_class, "il2cpp_image_get_class")(image, index);
    }

    size_t image_get_class_count(const Il2CppImage* image) const {
        return Expect(functions.il2cpp_image_get_class_count, "il2cpp_image_get_class_count")(image);
    }

    const char* image_get_name(const Il2CppImage* image) const {
        return Expect(functions.il2cpp_image_get_name, "il2cpp_image_get_name")(image);
    }

    MethodInfo* class_get_methods(const Il2CppClass* klass, const void* const* iter) const {
        return Expect(functions.il2cpp_class_get_methods, "il2cpp_class_get_methods")(klass, iter);
    }

    const char* class_get_name(const Il2CppClass* klass) const {
        return Expect(functions.il2cpp_class_get_name, "il2cpp_class_get_name")(klass);
    }

    const char* class_get_namespace(const Il2CppClass* klass) const {
        return Expect(functions.il2cpp_class_get_namespace, "il2cpp_class_get_namespace")(klass);
    }

    Il2CppClass* class_get_parent(const Il2CppClass* klass) const {
        if (!functions.il2cpp_class_get_parent) return nullptr;
        return functions.il2cpp_class_get_parent(klass);
    }

    bool class_is_valuetype(const Il2CppClass* klass) const {
        if (!functions.il2cpp_class_is_valuetype) return false;
        return functions.il2cpp_class_is_valuetype(klass);
    }

    bool class_is_enum(const Il2CppClass* klass) const {
        if (!functions.il2cpp_class_is_enum) return false;
        return functions.il2cpp_class_is_enum(klass);
    }

    int class_get_flags(const Il2CppClass* klass) const {
        if (!functions.il2cpp_class_get_flags) return 0;
        return functions.il2cpp_class_get_flags(klass);
    }

    const char* method_get_name(const MethodInfo* method) const {
        return Expect(functions.il2cpp_method_get_name, "il2cpp_method_get_name")(method);
    }

    Il2CppType* method_get_return_type(const MethodInfo* method) const {
        if (!functions.il2cpp_method_get_return_type) return nullptr;
        return functions.il2cpp_method_get_return_type(method);
    }

    uint32_t method_get_param_count(const MethodInfo* method) const {
        if (!functions.il2cpp_method_get_param_count) return 0;
        return functions.il2cpp_method_get_param_count(method);
    }

    Il2CppType* method_get_param(const MethodInfo* method, uint32_t index) const {
        if (!functions.il2cpp_method_get_param) return nullptr;
        return functions.il2cpp_method_get_param(method, index);
    }

    int field_get_flags(const FieldInfo* field) const {
        if (!functions.il2cpp_field_get_flags) return 0;
        return functions.il2cpp_field_get_flags(field);
    }

    const char* field_get_name(const FieldInfo* field) const {
        if (!functions.il2cpp_field_get_name) return "";
        return functions.il2cpp_field_get_name(field);
    }

    size_t field_get_offset(const FieldInfo* field) const {
        if (!functions.il2cpp_field_get_offset) return 0;
        return functions.il2cpp_field_get_offset(field);
    }

    Il2CppType* field_get_type(const FieldInfo* field) const {
        if (!functions.il2cpp_field_get_type) return nullptr;
        return functions.il2cpp_field_get_type(field);
    }

    const char* type_get_name(const Il2CppType* type) const {
        if (!functions.il2cpp_type_get_name) return "";
        return functions.il2cpp_type_get_name(type);
    }

    bool type_is_byref(const Il2CppType* type) const {
        if (!functions.il2cpp_type_is_byref) return false;
        return functions.il2cpp_type_is_byref(type);
    }

    uint32_t type_get_attrs(const Il2CppType* type) const {
        if (!functions.il2cpp_type_get_attrs) return 0;
        return functions.il2cpp_type_get_attrs(type);
    }

    Il2CppClass* class_get_interfaces(const Il2CppClass* klass, const void* const* iter) const {
        if (!functions.il2cpp_class_get_interfaces) return nullptr;
        return functions.il2cpp_class_get_interfaces(klass, iter);
    }

    FieldInfo* class_get_fields(const Il2CppClass* klass, const void* const* iter) const {
        if (!functions.il2cpp_class_get_fields) return nullptr;
        return functions.il2cpp_class_get_fields(klass, iter);
    }

private:
    template <typename Fn>
    static Fn Expect(Fn fn, const char* name) {
        if (!fn) {
            throw std::runtime_error(std::string("Missing function pointer: ") + name);
        }
        return fn;
    }
};

bool VerifyPointer(const Il2CppApi& il2cpp, uintptr_t pointer) {
    auto base = reinterpret_cast<uintptr_t>(il2cpp.game_assembly.handle);
    return pointer > base && pointer < base + il2cpp.game_assembly.size;
}

std::string SafeString(const char* ptr) {
    return ptr ? std::string(ptr) : std::string();
}

void DumpMethods(const Il2CppApi& il2cpp) {
    std::unordered_map<std::string, size_t> name_map;
    std::unordered_map<std::string, uint32_t> duplicates;

    auto domain = il2cpp.domain_get();
    size_t assembly_count = 0;
    auto assemblies = il2cpp.domain_get_assemblies(domain, &assembly_count);

    for (size_t i = 0; i < assembly_count; ++i) {
        auto assembly = assemblies[i];
        if (!assembly) continue;

        auto image = il2cpp.assembly_get_image(assembly);
        auto class_count = il2cpp.image_get_class_count(image);

        for (size_t j = 0; j < class_count; ++j) {
            auto klass = il2cpp.image_get_class(image, j);
            if (!klass) continue;

            std::string class_name = SafeString(il2cpp.class_get_name(klass));
            std::string class_namespace = SafeString(il2cpp.class_get_namespace(klass));
            if (!class_namespace.empty()) class_namespace.append(".");

            const void* method_iter = nullptr;
            while (auto method_info = il2cpp.class_get_methods(klass, &method_iter)) {
                auto pointer = reinterpret_cast<uintptr_t>(method_info->method_pointer);
                if (!VerifyPointer(il2cpp, pointer)) continue;

                std::string method_name = SafeString(il2cpp.method_get_name(method_info));
                std::string description = class_namespace + class_name + "::" + method_name;

                std::string unique_description = description;
                if (name_map.count(description)) {
                    auto count = ++duplicates[description];
                    unique_description = description + "_" + std::to_string(count);
                }

                name_map.emplace(unique_description, pointer - reinterpret_cast<uintptr_t>(il2cpp.game_assembly.handle));
            }
        }
    }

    std::ofstream file("methods.json");
    file << "{\n";
    size_t index = 0;
    for (const auto& [name, address] : name_map) {
        file << "  \"" << name << "\": \"0x" << std::hex << address << "\"";
        if (++index != name_map.size()) file << ",";
        file << "\n";
    }
    file << "}\n";

    std::cout << name_map.size() << " valid methods found and saved to methods.json\n";
}

void WriteFields(const Il2CppApi& il2cpp, std::ostringstream& output, const Il2CppClass* klass, bool is_value_type) {
    output << "\n\t// Fields\n";

    const void* field_iter = nullptr;
    while (auto field = il2cpp.class_get_fields(klass, &field_iter)) {
        int flags = il2cpp.field_get_flags(field);
        int access = flags & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
        case FIELD_ATTRIBUTE_PRIVATE: output << "\tprivate "; break;
        case FIELD_ATTRIBUTE_PUBLIC: output << "\tpublic "; break;
        case FIELD_ATTRIBUTE_FAMILY: output << "\tprotected "; break;
        case FIELD_ATTRIBUTE_ASSEMBLY:
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM: output << "\tinternal "; break;
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM: output << "\tprotected internal "; break;
        default: output << "\t"; break;
        }

        bool is_static = false;
        if (flags & FIELD_ATTRIBUTE_LITERAL) {
            output << "const ";
        } else {
            if (flags & FIELD_ATTRIBUTE_STATIC) {
                is_static = true;
                output << "static ";
            }
            if (flags & FIELD_ATTRIBUTE_INIT_ONLY) {
                output << "readonly ";
            }
        }

        auto field_type = il2cpp.field_get_type(field);
        size_t field_offset = il2cpp.field_get_offset(field);
        if (is_value_type && !is_static && field_offset > 0) {
            field_offset -= 0x10;
        }

        output << SafeString(il2cpp.type_get_name(field_type)) << ' '
               << SafeString(il2cpp.field_get_name(field)) << "; // 0x" << std::hex << field_offset << "\n";
    }
}

void WriteMethods(const Il2CppApi& il2cpp, std::ostringstream& output, const Il2CppClass* klass) {
    output << "\n\t// Methods\n";

    const void* method_iter = nullptr;
    while (auto method = il2cpp.class_get_methods(klass, &method_iter)) {
        output << "\n";
        auto pointer = reinterpret_cast<uintptr_t>(method->method_pointer);
        if (pointer != 0) {
            auto offset = pointer - reinterpret_cast<uintptr_t>(il2cpp.game_assembly.handle);
            output << "\t// RVA: 0x" << std::hex << offset << " VA: 0x" << std::hex << (offset + 0x180000000ULL) << "\n\t";
        } else {
            output << "\t// RVA: 0x0 VA: 0x0\n\t";
        }

        int flags = static_cast<int>(method->flags);
        int access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
        switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE: output << "private "; break;
        case METHOD_ATTRIBUTE_PUBLIC: output << "public "; break;
        case METHOD_ATTRIBUTE_FAMILY: output << "protected "; break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM: output << "internal "; break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM: output << "protected internal "; break;
        default: break;
        }

        if (flags & METHOD_ATTRIBUTE_STATIC) output << "static ";
        if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
            output << "abstract ";
            if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) output << "override ";
        } else if ((flags & METHOD_ATTRIBUTE_FINAL) && (flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            output << "sealed override ";
        } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
            if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) output << "virtual ";
            else output << "override ";
        }
        if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) output << "extern ";

        auto return_type = il2cpp.method_get_return_type(method);
        if (il2cpp.type_is_byref(return_type)) output << "ref ";

        output << SafeString(il2cpp.type_get_name(return_type)) << ' ' << SafeString(il2cpp.method_get_name(method)) << '(';

        auto param_count = il2cpp.method_get_param_count(method);
        for (uint32_t i = 0; i < param_count; ++i) {
            auto param = il2cpp.method_get_param(method, i);
            auto attrs = static_cast<int>(il2cpp.type_get_attrs(param));
            if (il2cpp.type_is_byref(param)) {
                if ((attrs & PARAM_ATTRIBUTE_OUT) && !(attrs & PARAM_ATTRIBUTE_IN)) output << "out ";
                else if ((attrs & PARAM_ATTRIBUTE_IN) && !(attrs & PARAM_ATTRIBUTE_OUT)) output << "in ";
                else output << "ref ";
            }
            output << SafeString(il2cpp.type_get_name(param));
            if (i + 1 != param_count) output << ", ";
        }
        output << ") { }\n";
    }
}

void WriteClass(const Il2CppApi& il2cpp, std::ostringstream& output, const Il2CppClass* klass) {
    output << "\n// Namespace: " << SafeString(il2cpp.class_get_namespace(klass)) << "\n";

    int flags = il2cpp.class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) output << "[Serializable]\n";

    int visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
    case TYPE_ATTRIBUTE_PUBLIC:
    case TYPE_ATTRIBUTE_NESTED_PUBLIC: output << "public "; break;
    case TYPE_ATTRIBUTE_NESTED_PRIVATE: output << "private "; break;
    case TYPE_ATTRIBUTE_NESTED_FAMILY: output << "protected "; break;
    case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: output << "protected internal "; break;
    case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
    case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        output << "internal ";
        break;
    default: break;
    }

    bool is_value_type = il2cpp.class_is_valuetype(klass);
    bool is_enum = il2cpp.class_is_enum(klass);

    if ((flags & TYPE_ATTRIBUTE_ABSTRACT) && (flags & TYPE_ATTRIBUTE_SEALED)) output << "static ";
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && (flags & TYPE_ATTRIBUTE_ABSTRACT)) output << "abstract ";
    else if (!is_value_type && !is_enum && (flags & TYPE_ATTRIBUTE_SEALED)) output << "sealed ";

    if (flags & TYPE_ATTRIBUTE_INTERFACE) output << "interface ";
    else if (is_enum) output << "enum ";
    else if (is_value_type) output << "struct ";
    else output << "class ";

    std::string name = SafeString(il2cpp.class_get_name(klass));
    output << name;

    std::vector<std::string> extends;
    if (auto parent = il2cpp.class_get_parent(klass)) {
        std::string parent_name = SafeString(il2cpp.class_get_name(parent));
        if (!is_value_type && !is_enum && parent_name != "Object") extends.push_back(parent_name);
    }

    const void* interface_iter = nullptr;
    while (auto interface_type = il2cpp.class_get_interfaces(klass, &interface_iter)) {
        extends.push_back(SafeString(il2cpp.class_get_name(interface_type)));
    }

    if (!extends.empty()) {
        output << " : ";
        for (size_t i = 0; i < extends.size(); ++i) {
            output << extends[i];
            if (i + 1 != extends.size()) output << ", ";
        }
    }

    output << "\n{";
    WriteFields(il2cpp, output, klass, is_value_type);
    WriteMethods(il2cpp, output, klass);
    output << "}\n";
}

void DumpCSharp(const Il2CppApi& il2cpp) {
    std::ostringstream output;
    auto domain = il2cpp.domain_get();
    size_t assembly_size = 0;
    auto assemblies = il2cpp.domain_get_assemblies(domain, &assembly_size);

    for (size_t i = 0; i < assembly_size; ++i) {
        auto assembly = assemblies[i];
        if (!assembly) continue;

        auto image = il2cpp.assembly_get_image(assembly);
        output << "// Image " << i << ": " << SafeString(il2cpp.image_get_name(image)) << "\n";

        auto class_count = il2cpp.image_get_class_count(image);
        for (size_t j = 0; j < class_count; ++j) {
            auto klass = il2cpp.image_get_class(image, j);
            if (klass) WriteClass(il2cpp, output, klass);
        }
    }

    std::ofstream file("dump.cs", std::ios::binary);
    file << output.str();
}

DWORD WINAPI DumpThread(LPVOID) {
    ::Sleep(10000);
    ::AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    std::cout << "honkai-dumper" << std::endl;
    std::cout << "dumping" << std::endl;

    if (auto api = Il2CppApi::CreateFromLoadedModules()) {
        try {
            DumpMethods(*api);
            DumpCSharp(*api);
            std::cout << "done" << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Error during dump: " << ex.what() << std::endl;
        }
    } else {
        std::cerr << "Failed to initialize IL2CPP API" << std::endl;
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        CreateThread(nullptr, 0, DumpThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

