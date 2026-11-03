#[macro_export]
macro_rules! obfstring {
    ($s:expr) => {
        $crate::libobfstr::obfstring!($s)
    };
}

#[macro_export]
macro_rules! debug_msg {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            alloc::format!($($arg)*)
        }
        #[cfg(not(debug_assertions))]
        {
            alloc::string::String::new()
        }
    };
}
