<script lang="ts" setup>
/**
 * La primera pantalla de Vasak Connect.
 *
 * Da la bienvenida y **lista los escritorios de VasakOS que aparecen en la red**
 * (descubrimiento por mDNS, del lado de Rust). Todavía no parea: el botón de
 * vincular y el SAS llegan en el PR siguiente. Todo lo que dibuja sale de
 * `@vasakgroup/vue-libvasak` y de los tokens del sistema —colores, radios y
 * sombras del esquema de VasakOS (decisión 8 del taller)—; nada de paletas
 * propias ni de la de Tailwind.
 *
 * No hay marco de ventana: en un teléfono la ventana la gobierna el sistema.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { useI18n } from '@vasakgroup/tauri-plugin-i18n';
import { EmptyState, StatusDot } from '@vasakgroup/vue-libvasak';
import { onMounted, onUnmounted, ref } from 'vue';

/** Lo que anuncia un escritorio, igual que `PeerInfo` del contrato (`wire`). */
interface Peer {
	device_id: string;
	name: string;
	kind: 'phone' | 'tablet' | 'desktop' | 'unknown';
	protocol_version: number;
	fingerprint: string;
}

const { t } = useI18n();

const peers = ref<Peer[]>([]);
let unlisten: UnlistenFn | null = null;
// Si el componente se desmonta mientras el `listen`/`invoke` de arranque siguen
// pendientes, hay que soltar lo que llegue tarde. Sin esto, un `listen` que
// resuelve después del desmontaje deja el oyente colgado para siempre y arranca
// un descubrimiento sin componente que lo gobierne.
let disposed = false;

onMounted(async () => {
	try {
		// Suscribirse ANTES de arrancar, para no perder el primer evento; igual se
		// pide la lista actual por si ya había algo visto.
		const un = await listen<Peer[]>('peers-changed', (evento) => {
			peers.value = evento.payload ?? [];
		});
		if (disposed) {
			un();
			return;
		}
		unlisten = un;

		await invoke('discovery_start');
		if (disposed) {
			// Se desmontó durante el arranque: deshacerlo, o queda navegando solo.
			invoke('discovery_stop').catch(() => {});
			return;
		}

		// `?? []` por si `invoke` no devuelve nada: la lista tiene que seguir siendo
		// un arreglo o el `v-for` y el `.length` del template fallan.
		const descubiertos = (await invoke<Peer[]>('discovered_peers')) ?? [];
		// Se pudo desmontar durante esta última espera: no escribir el estado de un
		// componente que ya no está.
		if (disposed) {
			return;
		}
		peers.value = descubiertos;
	} catch (error) {
		console.error('No se pudo iniciar el descubrimiento', error);
	}
});

onUnmounted(() => {
	// Marcar ANTES de limpiar: lo que esté pendiente en `onMounted` lo ve y se
	// suelta solo.
	disposed = true;
	if (unlisten !== null) {
		unlisten();
	}
	// Dejar de navegar al salir; si falla no hay nada que hacer salvo registrarlo.
	invoke('discovery_stop').catch((error) => {
		console.error('No se pudo detener el descubrimiento', error);
	});
});
</script>

<template>
  <main class="flex min-h-dvh flex-col items-center gap-6 bg-ui-bg p-6">
    <section
      class="mt-6 flex w-full max-w-sm flex-col items-center gap-5 rounded-corner-l bg-ui-surface/70 p-6 shadow-surface-l">
      <EmptyState
        :title="t('inicio.titulo')"
        :note="t('inicio.descripcion')"
        icon="network-wireless"
        icon-type="symbol" />

      <div class="flex items-center gap-2">
        <StatusDot tone="neutral" :label="t('inicio.estado.sinVincular')" />
        <span class="text-tx-muted">{{ t('inicio.estado.sinVincular') }}</span>
      </div>
    </section>

    <section class="flex w-full max-w-sm flex-col gap-3">
      <h2 class="px-1 text-sm font-medium text-tx-muted">
        {{ t('inicio.descubiertos.titulo') }}
      </h2>

      <p
        v-if="peers.length === 0"
        class="rounded-corner-m bg-ui-surface/50 px-4 py-6 text-center text-tx-muted">
        {{ t('inicio.descubiertos.buscando') }}
      </p>

      <ul v-else class="flex flex-col gap-2">
        <li
          v-for="peer in peers"
          :key="peer.device_id"
          class="flex items-center justify-between rounded-corner-m bg-ui-surface/70 px-4 py-3 shadow-surface-s">
          <span class="font-medium text-tx-main">{{ peer.name }}</span>
          <span class="text-sm text-tx-muted">{{ t(`inicio.tipo.${peer.kind}`) }}</span>
        </li>
      </ul>
    </section>
  </main>
</template>
