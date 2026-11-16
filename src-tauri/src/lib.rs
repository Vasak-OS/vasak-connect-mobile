//! Punto de entrada de una aplicación de VasakOS.
//!
//! Lo que hay acá no es decoración: cada pieza resuelve algo que en las
//! aplicaciones reales del escritorio se rompió al menos una vez.

mod locales;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        // El idioma de la sesión. **Con la ruta explícita de los catálogos**:
        // el plugin sólo prueba rutas relativas al ejecutable y al directorio
        // de trabajo, y ninguna existe cuando el binario está en /usr/bin. Sin
        // esto, un paquete instalado muestra las claves crudas
        // («views.home.title») en lugar de los textos. Ver `locales.rs`.
        .plugin(tauri_plugin_i18n_vsk::init_with_path(
            Some(locales::idioma_del_sistema()),
            locales::directorio(),
        ))
        .plugin(tauri_plugin_shell::init());

    // Plugins sólo de escritorio: sus crates no compilan para Android (ver
    // `Cargo.toml`). `vicons` arrastra `gtk`, y `config-manager` 2.13 usa su
    // módulo `desktop` sin condicionar por plataforma. En móvil el esquema de
    // color sale del piso de `main.css` hasta que el pareo traiga el de la PC.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        builder = builder
            .plugin(tauri_plugin_config_manager::init())
            .plugin(tauri_plugin_vicons::init());
    }

    builder
        .run(tauri::generate_context!())
        .expect("error al ejecutar la aplicación");
}
