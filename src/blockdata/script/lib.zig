const std = @import("std");
const script = @import("./script.zig");

const ScriptError = error{
    /// Something did a non-minimal push; for more information see
    /// <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#push-operators>
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumbericOverflow,
    /// Can not find the spent output.
    UnkownSpentOutput,
    /// Can not serialize the spending transaction.
    Serialization,
};

pub fn scritt_error_to_string(self: ScriptError) []const u8 {
    switch (self) {
        ScriptError.NonMinimalPush => return "non-minimal datapush",
        ScriptError.EarlyEndOfScript => return "unexpected end of script",
        ScriptError.NumbericOverflow => return "numberic overflow (number on stack larger than 4 bytes)",
        ScriptError.UnkownSpentOutput => return "unknown spent output",
        ScriptError.Serialization => return "can not serialize the spending transaction in Transaction::verify()",
    }
}

/// Decodes an integer in script format without non-minimal error.
///
/// The overflow error for slices over 4 bytes long is still there.
/// See ['read_scriptint'] for a description of some subtleties of
/// this function.
pub fn read_scriptint_non_minimal(v: []const u8) !i64 {
    if (v.len == 0) {
        return 0;
    }
    if (v.len > 4) {
        return ScriptError.NumbericOverflow;
    }

    return scriptint_parse(v);
}

fn scriptint_parse(v: []const u8) i64 {
    var ret: i64 = 0;
    var sh: u6 = 0;
    for (v) |byte| {
        ret += @as(i64, byte) << sh;
        sh += 8;
    }
    const last_byte = v[v.len - 1];
    if ((last_byte & 0x80) != 0) {
        ret &= (@as(i64, 1) << (sh - 1)) - 1; // 使用 u6 类型的位移
        ret = -ret;
    }
    return ret;
}

/// Decodes a boolean.
///
/// This is like "`read_scriptint` then map 0 to false and everything
/// else as true", exepect that the overflow rules don't apply.
pub fn readScriptBool(v: []const u8) bool {
    if (v.len == 0) {
        return false;
    }

    const last = v[v.len - 1];
    const rest = v[0 .. v.len - 1];

    var allZero = true;
    for (rest) |item| {
        if (item != 0) {
            allZero = false;
            break;
        }
    }

    return !((last & ~@as(u8, 0x80)) == 0 and allZero);
}

fn opcodeToVerify(opcode: ?script.OpCodeType) ?script.OpCodeType {
    if (opcode) |code| {
        switch (code) {
            .OP_EQUAL => return script.OpCodeType.OP_EQUALVERIFY,
            .OP_NUMEQUAL => return script.OpCodeType.OP_NUMEQUALVERIFY,
            .OP_CHECKSIG => return script.OpCodeType.OP_CHECKSIGVERIFY,
            .OP_CHECKMULTISIG => return script.OpCodeType.OP_CHECKMULTISIGVERIFY,
            else => return null,
        }
    }

    return null;
}
