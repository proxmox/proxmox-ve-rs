#[allow(unused_macros)]
macro_rules! get_fabrics_config {
    () => {{
        // Get current function name
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let mut name = type_name_of(f);

        // Find and cut the rest of the path
        name = match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        };
        let real_filename = format!("tests/fabric/cfg/{name}/fabrics.cfg");
        &std::fs::read_to_string(real_filename).expect("cannot find config file")
    }};
}

#[allow(unused_macros)]
macro_rules! reference_name {
    ($suffix:expr) => {{
        // Get current function name
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let mut name = type_name_of(f);

        // Find and cut the rest of the path
        name = match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        };
        format!("{name}_{}", $suffix)
    }};
}

#[allow(unused_imports)]
pub(crate) use get_fabrics_config;
#[allow(unused_imports)]
pub(crate) use reference_name;
