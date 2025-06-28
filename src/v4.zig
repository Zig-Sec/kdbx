const fields = @import("v4/fields.zig");

pub const Field = fields.Field;
pub const FieldTag = fields.FieldTag;
pub const VField = fields.VField;

const header = @import("v4/header.zig");
pub const HVersion = header.HVersion;
pub const Header = header.Header;

const keys = @import("v4/keys.zig");
pub const Keys = keys.Keys;

const xml = @import("v4/xml.zig");
pub const XML = xml.XML;
pub const Meta = xml.Meta;
pub const Entry = xml.Entry;
pub const Group = xml.Group;
pub const Icon = xml.Icon;
pub const AutoType = xml.AutoType;
pub const KeyValue = xml.KeyValue;
pub const Times = xml.Times;
pub const parseXml = xml.parseXml;
pub const Binary = xml.Binary;

const inner_header = @import("v4/inner_header.zig");
pub const InnerFieldTag = inner_header.InnerFieldTag;
pub const InnerHeader = inner_header.InnerHeader;

const body = @import("v4/body.zig");
pub const Body = body.Body;

const tests = @import("v4/tests.zig");

test "all v4 tests" {
    _ = fields;
    _ = header;
    _ = xml;
    _ = keys;
    _ = inner_header;
    _ = body;
    _ = tests;
}
