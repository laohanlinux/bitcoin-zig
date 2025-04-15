const std = @import("std");
const blockdata = @import("../blockdata/lib.zig");
const hashes = @import("../hashes/lib.zig");
const util = @import("../util/lib.zig");
const Script = blockdata.script.Script;
const local = @import("lib.zig");
const Address = local.address.Address;
const parseHex = hashes.engine.parseHexBytes;
const engine = hashes.engine;
const PublicKey = util.key.PublicKey;
const Error = local.address.Error;

fn roundtrips(addr: *const Address) !void {
    var area = std.heap.ArenaAllocator.init(addr.allocator);
    defer area.deinit();
    const from_str = try Address.fromString(area.allocator(), try addr.toString(area.allocator()));
    try std.testing.expectEqual(addr.*, from_str);
    const from_script = try Address.fromScript(area.allocator(), &addr.scriptPubKey(area.allocator()), addr.network);
    try std.testing.expectEqual(addr.*, from_script);
}

test "address" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const payload = engine.parseHexBytes(area.allocator(), "162c5ea71c0b23f5b9022ef047c4a86470a5b070")[0..20];
    const address = Address{
        .allocator = area.allocator(),
        .network = .bitcoin,
        .payload = .{ .PubkeyHash = payload.* },
    };
    const pubkey = address.scriptPubKey(area.allocator());
    // the pubkey hex formatted
    try std.testing.expectEqualSlices(u8, try engine.hex(area.allocator(), pubkey.asBytes()), "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac");
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    try std.testing.expectEqual(address.addressType().?, .P2pkh);
}

test "p2ppkh address base58" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const payload = engine.parseHexBytes(area.allocator(), "162c5ea71c0b23f5b9022ef047c4a86470a5b070")[0..20];
    const address = Address{
        .allocator = area.allocator(),
        .network = .bitcoin,
        .payload = .{ .PubkeyHash = payload.* },
    };
    const script = address.scriptPubKey(area.allocator());
    try std.testing.expectEqualSlices(u8, try engine.hex(area.allocator(), script.asBytes()), "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac");
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    try std.testing.expectEqual(address.addressType().?, .P2pkh);
}

test "p2pkh from key" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    {
        const key = try PublicKey.fromSlice(parseHex(area.allocator(), "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183"));
        const address = try Address.p2pkh(area.allocator(), &key, .bitcoin);
        try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");
    }

    {
        const key = try PublicKey.fromSlice(parseHex(area.allocator(), "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"));
        const address = try Address.p2pkh(area.allocator(), &key, .testnet);
        try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        try std.testing.expectEqual(address.addressType().?, .P2pkh);
    }
}

test "p2sh address base58" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const payload = engine.parseHexBytes(area.allocator(), "162c5ea71c0b23f5b9022ef047c4a86470a5b070");
    try std.testing.expect(payload.len == 20);
    const address = Address{
        .allocator = area.allocator(),
        .network = .bitcoin,
        .payload = .{ .ScriptHash = payload[0..20].* },
    };
    const script = address.scriptPubKey(area.allocator());
    try std.testing.expectEqualSlices(u8, try engine.hex(area.allocator(), script.asBytes()), "a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087");
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
    try std.testing.expectEqual(address.addressType().?, .P2sh);
}

test "p2sh parse" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const payload = parseHex(area.allocator(), "552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
    const script = try Script.fromBytes(area.allocator(), payload);
    const address = try Address.fromScript(area.allocator(), &script, .testnet);
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
    try std.testing.expectEqual(address.addressType().?, .P2sh);
}

test "p2wpkh" {
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    var key = try PublicKey.fromSlice(parseHex(area.allocator(), "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc"));
    const address = try Address.p2wpkh(area.allocator(), &key, .bitcoin);
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw");
    try std.testing.expectEqual(address.addressType().?, .P2wpkh);

    // Test uncompressed pubkey
    key.compressed = false;
    try std.testing.expectEqual(Address.p2wpkh(area.allocator(), &key, .bitcoin), Error.UncompressedPubkey);
}

test "p2wsh" {
    // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const script = try Script.fromBytes(area.allocator(), parseHex(area.allocator(), "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"));
    const address = Address.p2wsh(area.allocator(), &script, .bitcoin);
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej");
    try std.testing.expectEqual(address.addressType().?, .P2wsh);
}

test "p2shwpkh" {
    // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    var key = try PublicKey.fromSlice(parseHex(area.allocator(), "026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766"));
    const address = try Address.p2shwpkh(area.allocator(), &key, .bitcoin);
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
    try std.testing.expectEqual(address.addressType().?, .P2sh);
    // Test uncompressed pubkey
    key.compressed = false;
    try std.testing.expectEqual(Address.p2shwpkh(area.allocator(), &key, .bitcoin), Error.UncompressedPubkey);
}

test "p2shwsh" {
    // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
    var area = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer area.deinit();
    const script = try Script.fromBytes(area.allocator(), parseHex(area.allocator(), "522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae"));
    const address = Address.p2shwsh(area.allocator(), &script, .bitcoin);
    try std.testing.expectEqualSlices(u8, try address.toString(area.allocator()), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
    try std.testing.expectEqual(address.addressType().?, .P2sh);
}

// test "non existent segwit version" {
//     var area = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer area.deinit();
//     const version: u5 = 13;
//     // 40-byte program
//     const program = parseHex(area.allocator(), "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4");
//     const address = Address{
//         .network = .bitcoin,
//         .payload = .{ .WitnessProgram = .{
//             .version = version,
//             .program = program,
//         } },
//         .allocator = area.allocator(),
//     };
//     try roundtrips(&address);
// }
