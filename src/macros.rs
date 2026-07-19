#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            dbg!($($arg)*);
        }
    };
}

/// 混淆字符串
#[macro_export]
macro_rules! obfstr {
    ($s:expr) => {
        $crate::libobfstr::obfstr!($s)
    };
}

/// 混淆字节数组
#[macro_export]
macro_rules! obfbytes {
    ($s:expr) => {
        $crate::libobfstr::obfbytes!($s)
    };
}

/// 混淆字符串，返回 String
#[macro_export]
macro_rules! obfstring {
    ($s:expr) => {
        $crate::libobfstr::obfstring!($s)
    };
}

/// 编译时随机值
#[macro_export]
macro_rules! random {
    ($($tt:tt)*) => {
        $crate::libobfstr::random!($($tt)*)
    };
}
