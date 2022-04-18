const std = @import("std");
const string = []const u8;
const zorm = @import("zorm");
const ulid = @import("ulid");
const extras = @import("extras");
const http = @import("apple_pie");
const jwt = @import("jwt");
const cookies = @import("cookies");
const root = @import("root");
const pek = @import("pek");

const epoch: i64 = 1577836800000; // 'Jan 1 2020' -> unix milli

pub const sql = struct {
    //

    pub const Engine = zorm.engine(.sqlite3);
    pub var db: Engine = undefined;

    pub var factory = ulid.Factory.init(epoch, std.crypto.random);

    pub const Order = enum {
        asc,
        desc,
    };

    pub fn TableTypeMixin(comptime T: type) type {
        return struct {
            pub fn size(alloc: std.mem.Allocator) !u64 {
                const n = try db.first(alloc, u64, "select id from " ++ T.table_name ++ " order by id desc limit 1", .{});
                return n orelse 0;
            }

            pub fn all(alloc: std.mem.Allocator, comptime ord: Order) ![]const T {
                return try db.collect(alloc, T, "select * from " ++ T.table_name ++ " order by id " ++ @tagName(ord), .{});
            }
        };
    }

    pub fn ByKeyGen(comptime T: type) type {
        return struct {
            pub fn byKey(alloc: std.mem.Allocator, comptime key: std.meta.FieldEnum(T), value: extras.FieldType(T, key)) !?T {
                return try db.first(
                    alloc,
                    T,
                    "select * from " ++ T.table_name ++ " where " ++ @tagName(key) ++ " = ?",
                    foo(@tagName(key), value),
                );
            }

            pub fn byKeyAll(alloc: std.mem.Allocator, comptime key: std.meta.FieldEnum(T), value: extras.FieldType(T, key), comptime ord: Order) ![]const T {
                return try db.collect(
                    alloc,
                    T,
                    "select * from " ++ T.table_name ++ " where " ++ @tagName(key) ++ " = ? order by id " ++ @tagName(ord),
                    foo(@tagName(key), value),
                );
            }

            fn updateColumn(self: T, alloc: std.mem.Allocator, comptime key: std.meta.FieldEnum(T), value: extras.FieldType(T, key)) !void {
                return try db.exec(
                    alloc,
                    "update " ++ T.table_name ++ " set " ++ @tagName(key) ++ " = ? where id = ?",
                    merge(.{
                        foo(@tagName(key), value),
                        foo("id", self.id),
                    }),
                );
            }

            pub fn update(self: *T, alloc: std.mem.Allocator, comptime key: std.meta.FieldEnum(T), value: extras.FieldType(T, key)) !void {
                try updateColumn(self.*, alloc, key, value);
                @field(self, @tagName(key)) = value;
            }
        };
    }

    pub fn FindByGen(comptime S: type, comptime H: type, searchCol: std.meta.FieldEnum(H), selfCol: std.meta.FieldEnum(S)) type {
        const querystub = "select * from " ++ H.table_name ++ " where " ++ @tagName(searchCol) ++ " = ?";
        return struct {
            pub fn first(self: S, alloc: std.mem.Allocator, comptime key: std.meta.FieldEnum(H), value: extras.FieldType(H, key)) !?H {
                const query = querystub ++ " and " ++ @tagName(key) ++ " = ?";
                return try db.first(
                    alloc,
                    H,
                    query,
                    merge(.{
                        foo(@tagName(searchCol), @field(self, @tagName(selfCol))),
                        foo(@tagName(key), value),
                    }),
                );
            }
        };
    }

    fn foo(comptime name: string, value: anytype) Foo(name, @TypeOf(value)) {
        const T = @TypeOf(value);
        var x: Foo(name, T) = undefined;
        @field(x, name) = value;
        return x;
    }

    fn Foo(comptime name: string, comptime T: type) type {
        return Struct(&[_]std.builtin.TypeInfo.StructField{structField(name, T)});
    }

    fn Struct(comptime fields: []const std.builtin.TypeInfo.StructField) type {
        return @Type(.{ .Struct = .{ .layout = .Auto, .fields = fields, .decls = &.{}, .is_tuple = false } });
    }

    fn structField(comptime name: string, comptime T: type) std.builtin.TypeInfo.StructField {
        return .{ .name = name, .field_type = T, .default_value = null, .is_comptime = false, .alignment = @alignOf(T) };
    }

    fn merge(input: anytype) Merge(@TypeOf(input)) {
        const T = @TypeOf(input);
        var x: Merge(T) = undefined;
        inline for (std.meta.fields(T)) |item| {
            const a = @field(input, item.name);
            const b = std.meta.fields(item.field_type)[0].name;
            @field(x, b) = @field(a, b);
        }
        return x;
    }

    fn Merge(comptime T: type) type {
        var fields: []const std.builtin.TypeInfo.StructField = &.{};
        inline for (std.meta.fields(T)) |item| {
            const f = std.meta.fields(item.field_type)[0];
            fields = fields ++ &[_]std.builtin.TypeInfo.StructField{structField(f.name, f.field_type)};
        }
        return Struct(fields);
    }

    pub fn insert(alloc: std.mem.Allocator, value: anytype) !std.meta.Child(@TypeOf(value)) {
        const T = std.meta.Child(@TypeOf(value));
        @field(value, "id") = try nextId(alloc, T);
        comptime var parens: string = "";
        inline for (std.meta.fields(T)) |_, i| {
            if (i != 0) parens = parens ++ ", ";
            parens = parens ++ "?";
        }
        try db.exec(alloc, "insert into " ++ T.table_name ++ " values (" ++ parens ++ ")", value.*);
        return value.*;
    }

    fn nextId(alloc: std.mem.Allocator, comptime T: type) !u64 {
        return (try T.size(alloc)) + 1;
    }

    pub fn createTableT(alloc: std.mem.Allocator, eng: *Engine, comptime T: type) !void {
        const tI = @typeInfo(T).Struct;
        const fields = tI.fields;
        try createTable(alloc, eng, T.table_name, comptime colToCol(fields[0]), comptime fieldsToCols(fields[1..]));
    }

    fn createTable(alloc: std.mem.Allocator, eng: *Engine, comptime name: string, comptime pk: [2]string, comptime cols: []const [2]string) !void {
        if (try eng.doesTableExist(alloc, name)) {} else {
            std.log.scoped(.db).info("creating table '{s}' with primary column '{s}'", .{ name, pk[0] });
            try eng.exec(alloc, comptime std.fmt.comptimePrint("create table {s}({s} {s})", .{ name, pk[0], pk[1] }), .{});
        }
        inline for (cols) |item| {
            if (try eng.hasColumnWithName(alloc, name, item[0])) {} else {
                std.log.scoped(.db).info("adding column to '{s}': '{s}'", .{ name, item[0] });
                try eng.exec(alloc, comptime std.fmt.comptimePrint("alter table {s} add \"{s}\" {s}", .{ name, item[0], item[1] }), .{});
            }
        }
    }

    fn fieldsToCols(comptime fields: []const std.builtin.TypeInfo.StructField) []const [2]string {
        comptime {
            var result: [fields.len][2]string = undefined;
            for (fields) |item, i| {
                result[i] = colToCol(item);
            }
            return &result;
        }
    }

    fn colToCol(comptime field: std.builtin.TypeInfo.StructField) [2]string {
        return [_]string{
            field.name,
            typeToSqliteType(field.field_type),
        };
    }

    fn typeToSqliteType(comptime T: type) string {
        if (comptime std.meta.trait.isZigString(T)) {
            return "text";
        }
        switch (@typeInfo(T)) {
            .Struct, .Enum, .Union => if (@hasDecl(T, "BaseType")) return typeToSqliteType(T.BaseType),
            else => {},
        }
        return switch (T) {
            u16, u32, u64 => "int",
            else => @compileError("typeToSqliteType: " ++ @typeName(T)),
        };
    }

    // pub fn JsonStructSkipMixin(comptime S: type, comptime skips: []const std.meta.FieldEnum(S)) type {
    pub fn JsonStructSkipMixin(comptime S: type, comptime skips: []const string) type {
        return struct {
            pub fn jsonStringify(self: S, options: std.json.StringifyOptions, out_stream: anytype) !void {
                try out_stream.writeByte('{');
                var field_output = false;
                var child_options = options;
                if (child_options.whitespace) |*child_whitespace| {
                    child_whitespace.indent_level += 1;
                }
                inline for (std.meta.fields(S)) |Field| {
                    // don't include void fields
                    if (Field.field_type == void) continue;

                    var emit_field = true;

                    for (skips) |skp| {
                        // if (std.mem.eql(u8, @tagName(skp), Field.name)) {
                        if (std.mem.eql(u8, skp, Field.name)) {
                            emit_field = false;
                        }
                    }

                    if (emit_field) {
                        if (!field_output) {
                            field_output = true;
                        } else {
                            try out_stream.writeByte(',');
                        }
                        if (child_options.whitespace) |child_whitespace| {
                            try out_stream.writeByte('\n');
                            try child_whitespace.outputIndent(out_stream);
                        }
                        try std.json.stringify(Field.name, options, out_stream);
                        try out_stream.writeByte(':');
                        if (child_options.whitespace) |child_whitespace| {
                            if (child_whitespace.separator) {
                                try out_stream.writeByte(' ');
                            }
                        }
                        try std.json.stringify(@field(self, Field.name), child_options, out_stream);
                    }
                }
                if (field_output) {
                    if (options.whitespace) |whitespace| {
                        try out_stream.writeByte('\n');
                        try whitespace.outputIndent(out_stream);
                    }
                }
                try out_stream.writeByte('}');
            }
        };
    }
};

pub const www = struct {
    //

    pub var jwt_secret: string = "";

    pub const token = struct {
        const Payload = struct {
            iss: string, // issuer
            sub: string, // subject
            iat: i64, // issued-at
            exp: i64, // expiration
            nbf: u64, // not-before
        };

        pub fn veryifyRequest(request: http.Request) !string {
            const text = (try tokenFromRequest(request)) orelse return error.NoTokenFound;
            const payload = try jwt.validate(Payload, request.arena, .HS256, text, .{ .key = jwt_secret });
            return payload.sub;
        }

        fn tokenFromRequest(request: http.Request) !?string {
            const T = fn (http.Request) anyerror!?string;
            for (&[_]T{ tokenFromCookie, tokenFromHeader, tokenFromQuery }) |item| {
                if (try item(request)) |thetoken| {
                    return thetoken;
                }
            }
            return null;
        }

        fn tokenFromHeader(request: http.Request) !?string {
            const headers = try request.headers(request.arena);
            // extra check caused by https://github.com/Luukdegram/apple_pie/issues/70
            const auth = headers.get("Authorization") orelse headers.get("authorization");
            if (auth == null) return null;
            const ret = extras.trimPrefix(auth.?, "Bearer ");
            if (ret.len == auth.?.len) return null;
            return ret;
        }

        fn tokenFromCookie(request: http.Request) !?string {
            const headers = try request.headers(request.arena);
            const yum = try cookies.parse(request.arena, headers);
            return yum.get("jwt");
        }

        fn tokenFromQuery(request: http.Request) !?string {
            const q = try request.context.uri.queryParameters(request.arena);
            return q.get("jwt");
        }

        pub fn encodeMessage(alloc: std.mem.Allocator, msg: string) !string {
            const p = Payload{
                .iss = root.name ++ ".r" ++ root.build_options.version,
                .sub = msg,
                .iat = std.time.timestamp(),
                .exp = std.time.timestamp() + (std.time.s_per_day * 7),
                .nbf = epoch / std.time.ms_per_s,
            };
            return try jwt.encode(alloc, .HS256, p, .{ .key = jwt_secret });
        }
    };

    pub const SkipError = error{HttpNoOp};

    pub fn writePageResponse(alloc: std.mem.Allocator, response: *http.Response, request: http.Request, comptime name: string, data: anytype) !void {
        _ = request;
        try response.headers.put("Content-Type", "text/html");

        const w = response.writer();

        if (root.oxwww_allowjson) {
            const headers = try request.headers(alloc);
            // extra check caused by https://github.com/Luukdegram/apple_pie/issues/70
            if (std.mem.eql(u8, headers.get("Accept") orelse headers.get("accept") orelse "", "application/json")) {
                try std.json.stringify(data, .{}, w);
                return;
            }
        }

        const head = root.files.@"/_header.pek";
        const page = @field(root.files, name);
        const tmpl = comptime pek.parse(head ++ page);
        try pek.compile(root, alloc, w, tmpl, data);
    }

    pub fn assert(cond: bool, response: *http.Response, status: http.Response.Status, comptime fmt: string, args: anytype) !void {
        if (!cond) {
            return fail(response, status, fmt, args);
        }
    }

    pub fn fail(response: *http.Response, status: http.Response.Status, comptime fmt: string, args: anytype) (http.Response.Writer.Error || SkipError) {
        response.status_code = status;
        try response.writer().print(fmt ++ "\n", args);
        return error.HttpNoOp;
    }

    pub const HandlerFunc = fn next(void, *http.Response, http.Request, ?*const anyopaque) anyerror!void;

    pub fn Route(comptime f: anytype) HandlerFunc {
        return struct {
            pub fn next(_: void, response: *http.Response, request: http.Request, captures: ?*const anyopaque) !void {
                f({}, response, request, captures) catch |err| {
                    if (@as(anyerror, err) == error.HttpNoOp) return;
                    return err;
                };
            }
        }.next;
    }

    pub fn isLoggedIn(request: http.Request) !bool {
        const x = token.veryifyRequest(request) catch |err| switch (err) {
            error.NoTokenFound, error.InvalidSignature => return false,
            else => return err,
        };
        // don't need to waste hops to the db to check if its a value user ID because
        // if the signature is valid we know it came from us
        _ = x;
        return true;
    }

    pub fn redirectTo(response: *http.Response, dest: string) !void {
        try response.headers.put("Location", dest);
        try response.writeHeader(.found);
    }

    pub fn logout(_: void, response: *http.Response, request: http.Request, captures: ?*const anyopaque) !void {
        std.debug.assert(captures == null);
        _ = response;
        _ = request;

        try cookies.delete(response, "jwt");
        try redirectTo(response, "./");
    }
};
