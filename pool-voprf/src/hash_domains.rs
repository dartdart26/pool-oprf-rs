#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Domain {
    Key = 1,
    MaskSum = 2,
    Pad = 3,
    Masks = 4,
    MaskSumRandomness = 5,
}
