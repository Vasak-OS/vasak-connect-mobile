//! Punto de entrada de una aplicación de VasakOS.
//!
//! Lo que hay acá no es decoración: cada pieza resuelve algo que en las
//! aplicaciones reales del escritorio se rompió al menos una vez.

mod locales;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    construir_app()
        .run(tauri::generate_context!())
        .expect("error al ejecutar la aplicación");
}

/// Arma la aplicación con sus plugins, **sin arrancarla**.
///
/// Separado de `run` para poder probar el armado sin abrir una ventana ni
/// entrar al bucle de eventos: así el registro condicional de plugins —lo que
/// cambia entre escritorio y móvil— queda cubierto por una prueba en vez de
/// vivir sólo en el punto de entrada, que no se puede ejecutar en un test.
fn construir_app() -> tauri::Builder<tauri::Wry> {
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
}

#[cfg(test)]
mod pruebas {
    /// Armar la app no paniquea.
    ///
    /// `construir_app` es privada a propósito —se prueba acá adentro, en el
    /// mismo archivo— y registra los plugins sin `.run()`. En el host corre en
    /// modo escritorio, así que esta llamada ejecuta también el registro
    /// condicional de i18n, shell, config-manager y vicons; construir el
    /// `Builder` no abre ventana ni inicia gtk, eso recién pasaría en `.run()`.
    #[test]
    fn construir_app_no_paniquea() {
        let _ = super::construir_app();
    }
}
