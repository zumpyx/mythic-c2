#[macro_export]
macro_rules! obfstring {
    ($s:expr) => {
        $crate::libobfstr::obfstring!($s)
    };
}
