<script setup lang="ts">
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { useConfigStore } from '@vasakgroup/plugin-config-manager';
import { nextTick, onMounted, onUnmounted, type Ref, ref } from 'vue';
import { saveTheme } from '@/tools/theme-cache';
import WelcomeScreen from '@/views/WelcomeScreen.vue';

let unListenConfig: Ref<UnlistenFn | null> = ref(null);

// La primera lectura de la configuración va después del primer dibujo: en
// `onMounted` sin esperar, el layout se pinta con los valores por omisión y la
// configuración llega encima. Esperando a `nextTick`, la ventana ya está en
// pantalla cuando empieza la lectura, y si falla se avisa con el banner y se
// siguen usando los valores por defecto — una ventana con colores por omisión
// sigue siendo usable; una ventana que no monta no.
const configLoading = ref(true);
const configError = ref(false);

// En móvil no hay `config-manager` (su crate no compila para Android; ver
// `src-tauri/Cargo.toml`), así que no se intenta leer la configuración: los
// colores salen del piso del esquema en `main.css` —los de VasakOS por
// omisión— hasta que el pareo traiga el esquema de la PC. Sin esto, cada
// arranque en el teléfono mostraría el banner de error de configuración.
const esMovil = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

onMounted(async () => {
	// Que el layout se pinte primero, antes de cualquier lectura.
	await nextTick();

	if (esMovil) {
		configLoading.value = false;
		return;
	}

	const configStore = useConfigStore();

	try {
		// Recordar el tema aplicado para que el próximo arranque no parpadee.
		await configStore.loadConfig().then(() => saveTheme());
		configLoading.value = false;
	} catch (error: any) {
		configLoading.value = false;
		configError.value = true;
		console.error('Error al cargar configuración en App.vue', error);
	}

	// Fuera del `try` de la lectura: aunque esa falle o nunca resuelva, los
	// cambios de configuración de después tienen que poder aplicarse. Antes,
	// un fallo en la primera lectura dejaba la suscripción sin registrar y la
	// app se quedaba con los valores por defecto hasta reiniciar.
	try {
		unListenConfig.value = await listen('config-changed', async () => {
			document.startViewTransition(() => {
				configStore.loadConfig().then(() => saveTheme());
			});
		});
	} catch (error: any) {
		console.error('No se pudo escuchar los cambios de configuración', error);
	}
});

onUnmounted(() => {
	if (unListenConfig.value !== null) {
		unListenConfig.value();
	}
});
</script>

<template>
  <div v-if="configLoading" class="config-status">
    Cargando configuración…
  </div>
  <div v-else-if="configError" class="error-banner">
    Error al cargar configuración. Usando valores por defecto.
  </div>
  <WelcomeScreen />
</template>
