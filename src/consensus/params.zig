const std = @import("std");
const Network = @import("../network/constants.zig").Network;

/// 比特币主网的最低难度值
const MAX_BITS_BITCOIN = [4]u64{
    0x00000000ffff0000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
};

/// 测试网的最低难度值
const MAX_BITS_TESTNET = [4]u64{
    0x00000000ffff0000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
};

/// 回归测试网的最低难度值
const MAX_BITS_REGTEST = [4]u64{
    0x7fffff0000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
};

/// 影响链共识的参数
pub const Params = struct {
    /// 参数所适用的网络
    network: Network,
    /// BIP16 激活时间
    bip16_time: u32,
    /// BIP34 激活高度
    bip34_height: u32,
    /// BIP65 激活高度
    bip65_height: u32,
    /// BIP66 激活高度
    bip66_height: u32,
    /// 规则更改激活阈值
    rule_change_activation_threshold: u32,
    /// 矿工确认窗口
    miner_confirmation_window: u32,
    /// 工作量证明限制值
    pow_limit: [4]u64,
    /// 预期的区块生成时间间隔
    pow_target_spacing: u64,
    /// 难度重新计算间隔
    pow_target_timespan: u64,
    /// 是否允许最小难度区块
    allow_min_difficulty_blocks: bool,
    /// 是否禁用POW难度调整
    no_pow_retargeting: bool,

    /// 创建指定网络的参数集
    pub fn new(network: Network) Params {
        return switch (network) {
            .bitcoin => .{
                .network = .bitcoin,
                .bip16_time = 1333238400,
                .bip34_height = 227931,
                .bip65_height = 388381,
                .bip66_height = 363725,
                .rule_change_activation_threshold = 1916,
                .miner_confirmation_window = 2016,
                .pow_limit = MAX_BITS_BITCOIN,
                .pow_target_spacing = 10 * 60,
                .pow_target_timespan = 14 * 24 * 60 * 60,
                .allow_min_difficulty_blocks = false,
                .no_pow_retargeting = false,
            },
            .testnet => .{
                .network = .testnet,
                .bip16_time = 1333238400,
                .bip34_height = 21111,
                .bip65_height = 581885,
                .bip66_height = 330776,
                .rule_change_activation_threshold = 1512,
                .miner_confirmation_window = 2016,
                .pow_limit = MAX_BITS_TESTNET,
                .pow_target_spacing = 10 * 60,
                .pow_target_timespan = 14 * 24 * 60 * 60,
                .allow_min_difficulty_blocks = true,
                .no_pow_retargeting = false,
            },
            .regtest => .{
                .network = .regtest,
                .bip16_time = 1333238400,
                .bip34_height = 100000000,
                .bip65_height = 1351,
                .bip66_height = 1251,
                .rule_change_activation_threshold = 108,
                .miner_confirmation_window = 144,
                .pow_limit = MAX_BITS_REGTEST,
                .pow_target_spacing = 10 * 60,
                .pow_target_timespan = 14 * 24 * 60 * 60,
                .allow_min_difficulty_blocks = true,
                .no_pow_retargeting = true,
            },
        };
    }

    /// 计算难度调整间隔的区块数
    pub fn difficulty_adjustment_interval(self: *const Params) u64 {
        return self.pow_target_timespan / self.pow_target_spacing;
    }
};
