<think>我需要将`src/blockdata/opcodes.zig`中实现的比特币脚本操作码逻辑转换为一份markdown文档。我将组织结构如下：

1. 介绍比特币脚本操作码系统
2. 核心数据结构介绍
3. 操作码分类系统
4. 主要功能和方法
5. 测试和验证

让我基于代码内容创建这个文档。</think># 比特币脚本操作码系统

## 概述

比特币脚本是一种基于堆栈的简单语言，用于验证比特币交易。脚本由一系列操作码组成，这些操作码指示比特币节点如何执行脚本。本文档描述了一个用Zig语言实现的比特币脚本操作码系统。

## 核心数据结构

### `All` 结构体

`All`结构体代表一个比特币脚本操作码。

```zig
pub const All = struct {
    code: u8,
    // 方法...
};
```

**字段**:
- `code`: 一个8位无符号整数，表示操作码的字节值

**方法**:
- `into_u8(self: All) u8`: 将操作码转换为字节值
- `from_u8(b: u8) All`: 从字节值创建一个操作码
- `classify(self: All) Class`: 将操作码分类到其语义类型
- `format(...)`: 用于调试输出的格式化方法

### `all` 命名空间

`all`命名空间定义了所有标准比特币脚本操作码常量。

```zig
pub const all = struct {
    pub const OP_PUSHBYTES_0 = All{ .code = 0x00 };
    pub const OP_PUSHBYTES_1 = All{ .code = 0x01 };
    // ...更多操作码...
};
```

主要操作码类别:

1. **数据推送操作码** (0x00-0x4b):
   - `OP_PUSHBYTES_0` 到 `OP_PUSHBYTES_75`: 直接将1-75个字节推送到堆栈

2. **数据处理操作码** (0x4c-0x4e):
   - `OP_PUSHDATA1`: 下一个字节包含要推送的字节数
   - `OP_PUSHDATA2`: 下两个字节包含要推送的字节数
   - `OP_PUSHDATA4`: 下四个字节包含要推送的字节数

3. **常量操作码** (0x4f-0x60):
   - `OP_PUSHNUM_NEG1` 到 `OP_PUSHNUM_16`: 将整数-1到16推送到堆栈

4. **流控制操作码** (0x61-0x6a):
   - `OP_NOP`: 不执行任何操作
   - `OP_IF`, `OP_ELSE`, `OP_ENDIF`: 条件执行
   - `OP_VERIFY`: 验证栈顶元素
   - `OP_RETURN`: 立即终止脚本

5. **堆栈操作码** (0x6b-0x7d):
   - `OP_TOALTSTACK`, `OP_FROMALTSTACK`: 备用堆栈操作
   - `OP_DROP`, `OP_DUP`, `OP_SWAP`: 基本堆栈操作
   - `OP_2DROP`, `OP_2DUP`, `OP_3DUP`: 复合堆栈操作

6. **字符串操作码** (0x7e-0x82):
   - `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_SIZE`

7. **位操作码** (0x83-0x86):
   - `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`

8. **比较操作码** (0x87-0x8a):
   - `OP_EQUAL`, `OP_EQUALVERIFY`

9. **算术操作码** (0x8b-0x99):
   - `OP_1ADD`, `OP_1SUB`, `OP_ADD`, `OP_SUB`等

10. **逻辑操作码** (0x9a-0xa5):
    - `OP_BOOLAND`, `OP_BOOLOR`, `OP_NUMEQUAL`等

11. **加密操作码** (0xa6-0xaf):
    - `OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`, `OP_HASH160`, `OP_HASH256`
    - `OP_CHECKSIG`, `OP_CHECKMULTISIG`等

12. **NOP操作码** (0xb0-0xb9):
    - `OP_NOP1` 到 `OP_NOP10`
    - `OP_CLTV` (CheckLockTimeVerify)
    - `OP_CSV` (CheckSequenceVerify)

13. **保留操作码** (0xba-0xff):
    - `OP_RETURN_186` 到 `OP_RETURN_255`

## 操作码分类系统

### `Class` 联合枚举

`Class`联合枚举根据操作码的行为对其进行分类。

```zig
pub const Class = union(enum) {
    PushNum: i32,
    PushBytes: u32,
    ReturnOp,
    IllegalOp,
    NoOp,
    Ordinary: Ordinary,
    // 方法...
};
```

**类别**:
- `PushNum`: 将数字推入堆栈的操作码
- `PushBytes`: 将字节推入堆栈的操作码
- `ReturnOp`: 执行时使脚本失败的操作码
- `IllegalOp`: 即使未执行也会使脚本失败的操作码
- `NoOp`: 不执行任何操作的操作码
- `Ordinary`: 未被上述分类覆盖的普通操作码

### `Ordinary` 枚举

`Ordinary`枚举表示未被特殊处理的普通操作码。

```zig
pub const Ordinary = enum(u8) {
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    // ...更多普通操作码...
    
    pub fn into_u8(self: Ordinary) u8 {
        return @intFromEnum(self);
    }
};
```

## 主要功能和方法

### 操作码分类

`classify`方法将操作码按照其功能分类:

```zig
pub fn classify(self: All) Class {
    const code = self.code;
    
    if (code == 0x00) {
        return Class{ .PushBytes = 0 };
    } else if (code >= 0x01 and code <= 0x4b) {
        return Class{ .PushBytes = code };
    }
    // ...更多分类逻辑...
}
```

### 操作码格式化

`format`方法为调试和显示提供了格式化功能:

```zig
pub fn format(self: All, ...) !void {
    // 格式化逻辑...
}
```

## 测试和验证

该实现包含两个测试函数来验证功能的正确性:

### 操作码分类测试

```zig
test "opcode classification" {
    try std.testing.expectEqual(Class{ .PushBytes = 0 }, all.OP_PUSHBYTES_0.classify());
    try std.testing.expectEqual(Class{ .PushNum = 1 }, all.OP_PUSHNUM_1.classify());
    try std.testing.expectEqual(Class.ReturnOp, all.OP_RETURN.classify());
    try std.testing.expectEqual(Class.NoOp, all.OP_NOP.classify());
}
```

### 字节表示往返测试

```zig
test "str_roundtrip" {
    var unique = std.AutoHashMap(u8, void).init(std.testing.allocator);
    defer unique.deinit();
    
    // 测试几个操作码的往返转换
    inline for (.{
        all.OP_PUSHBYTES_0,
        all.OP_PUSHBYTES_1,
        // ...更多操作码...
    }) |op| {
        const code = op.into_u8();
        try unique.put(code, {});
        
        const roundtrip = All.from_u8(code);
        try std.testing.expectEqual(code, roundtrip.into_u8());
    }
}
```

## 注意事项

当前实现中存在一个类型转换错误:
```
@intCast(i32, code - 0x50)
```
在新版Zig中，应改为:
```
@as(i32, code - 0x50)
```
或者不需要显式转换。

