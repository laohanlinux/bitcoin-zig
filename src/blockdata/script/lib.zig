const std = @import("std");

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
    // var ret: i64 = 0;
    // var sh: i32 = 0;
    // const len = v.len;
    // for (v) |n| {
    //     const move_n = @as(i64, n);
    //     //const left_low = @as(i64, sh);
    //     ret += (move_n << 1);
    //     sh += 8;
    // }
    //
    // if (v[len - 1] & 0x80 != 0) {
    //     ret &= (1 << (sh - 1)) - 1;
    //     ret = -ret;
    // }
    //
    // return ret;
    // Convert the byte slice to an i64

    // Ensure the slice is big enough to hold the i64
    if (v.len > @sizeOf(i64)) {
        @panic("it should not happen");
    }

    var result: i64 = 0;
    for (v) |byte| {
        const hi = result << 8;
        const low = @as(i64, byte);
        result = hi + low;
    }

    return result;
}
