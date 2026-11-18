<script lang="ts" setup>
/**
 * La primera pantalla de Vasak Connect.
 *
 * Lista los escritorios de VasakOS que aparecen en la red (descubrimiento por
 * mDNS) y deja **vincular** con uno: abre el pareo, muestra el código de
 * seguridad (SAS) que el escritorio también muestra, y fija el vínculo sólo si la
 * persona confirma que los dos códigos coinciden. Todo el I/O y la cripto están
 * del lado de Rust; acá sólo se dispara y se sigue por eventos.
 *
 * Lo que dibuja sale de `@vasakgroup/vue-libvasak` y de los tokens del sistema
 * —colores, radios y sombras del esquema de VasakOS (decisión 8)—; nada de
 * paletas propias ni de la de Tailwind. No hay marco de ventana: en un teléfono
 * la gobierna el sistema.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { useI18n } from '@vasakgroup/tauri-plugin-i18n';
import { EmptyState, StatusDot } from '@vasakgroup/vue-libvasak';
import { computed, onMounted, onUnmounted, ref } from 'vue';

/** Lo que anuncia un escritorio, igual que `PeerInfo` del contrato (`wire`). */
interface Peer {
	device_id: string;
	name: string;
	kind: 'phone' | 'tablet' | 'desktop' | 'unknown';
	protocol_version: number;
	fingerprint: string;
}

/** Un escritorio ya vinculado (persistido del lado de Rust). */
interface PairedPeer {
	device_id: string;
	name: string;
	kind: Peer['kind'];
	fingerprint: string;
}

/** Cómo terminó un pareo, igual que `PairingResultPayload` de Rust. */
interface PairingResult {
	device_id: string;
	status: 'paired' | 'rejected_local' | 'rejected_peer' | 'aborted' | 'error';
	message: string | null;
}

const { t } = useI18n();

const peers = ref<Peer[]>([]);
const paired = ref<PairedPeer[]>([]);
/** El pareo en curso: el escritorio elegido y el SAS cuando llega (`null` hasta). */
const pairing = ref<{ deviceId: string; name: string; sas: string | null } | null>(null);
/** El último resultado, para un cartel breve. */
const result = ref<PairingResult | null>(null);

const pairedIds = computed(() => new Set(paired.value.map((p) => p.device_id)));

let disposed = false;
const unlistens: UnlistenFn[] = [];

async function refreshPaired(): Promise<void> {
	paired.value = (await invoke<PairedPeer[]>('paired_peers')) ?? [];
}

/**
 * Registra un oyente y guarda su limpieza en el acto. Si el componente ya se
 * desmontó cuando la suscripción resuelve, se suelta ahí mismo: así un oyente que
 * se registra tarde no queda colgado (su limpieza no se perdería esperando a que
 * terminen las otras suscripciones).
 */
async function escuchar<T>(evento: string, manejar: (payload: T) => void): Promise<void> {
	const un = await listen<T>(evento, (e) => manejar(e.payload));
	if (disposed) {
		un();
	} else {
		unlistens.push(un);
	}
}

/** Empieza a parear con un escritorio: abre el diálogo y dispara el pareo. */
async function pair(peer: Peer): Promise<void> {
	result.value = null;
	pairing.value = { deviceId: peer.device_id, name: peer.name, sas: null };
	try {
		await invoke('pair_request', { deviceId: peer.device_id });
	} catch (error) {
		pairing.value = null;
		result.value = { device_id: peer.device_id, status: 'error', message: String(error) };
	}
}

/** La decisión de la persona sobre el SAS. El resultado llega por evento. */
async function confirm(accept: boolean): Promise<void> {
	try {
		await invoke('pair_confirm', { accept });
	} catch (error) {
		console.error('No se pudo enviar la confirmación', error);
	}
}

/** Los `device_id` con sesión de sincronización viva (del evento `sync-status`). */
const connected = ref<string[]>([]);
/** Los pareos para los que ya hay un `sync_connect` en vuelo, para no lanzar dos. */
const connecting = new Set<string>();
/** Escritorios que reaparecieron mientras su intento anterior seguía cerrándose:
 * se reconectan en cuanto ese intento termina. */
const pendingReconnect = new Set<string>();

/**
 * Asegura una sesión de sync con un escritorio vinculado y presente: si no hay una
 * en vuelo, abre `sync_connect` (comando de larga duración). Su promesa se resuelve
 * al cortarse la sesión. Si el escritorio se redescubre mientras el intento anterior
 * todavía se está cerrando, se anota y se reconecta al terminar —así una
 * desaparición/reaparición rápida no se pierde—. Sin reintento inmediato cuando NO
 * hubo redescubrimiento, a propósito, para no entrar en bucle si el escritorio rechaza.
 */
function ensureSync(peer: Peer): void {
	const id = peer.device_id;
	if (!pairedIds.value.has(id)) {
		return;
	}
	if (connecting.has(id)) {
		pendingReconnect.add(id);
		return;
	}
	connecting.add(id);
	invoke('sync_connect', { deviceId: id })
		.catch((error) => console.error('La sesión de sincronización terminó', error))
		.finally(() => {
			connecting.delete(id);
			if (pendingReconnect.delete(id)) {
				const presente = peers.value.find((p) => p.device_id === id);
				if (presente !== undefined) {
					ensureSync(presente);
				}
			}
		});
}

/** Intenta sincronizar con cada escritorio descubierto que esté vinculado. */
function syncDiscoveredPaired(): void {
	for (const peer of peers.value) {
		ensureSync(peer);
	}
}

onMounted(async () => {
	try {
		await escuchar<Peer[]>('peers-changed', (payload) => {
			peers.value = payload ?? [];
			// Apenas aparece un escritorio, si está vinculado se intenta sincronizar.
			syncDiscoveredPaired();
		});
		await escuchar<string>('pairing-sas', (payload) => {
			if (pairing.value !== null) {
				pairing.value.sas = payload;
			}
		});
		await escuchar<PairingResult>('pairing-result', (payload) => {
			pairing.value = null;
			result.value = payload;
			if (payload.status === 'paired') {
				refreshPaired()
					.then(() => syncDiscoveredPaired())
					.catch((error) => console.error('No se pudo refrescar los vinculados', error));
			}
		});
		await escuchar<{ device_id: string; connected: boolean }>('sync-status', (payload) => {
			const resto = connected.value.filter((id) => id !== payload.device_id);
			connected.value = payload.connected ? [...resto, payload.device_id] : resto;
		});
		if (disposed) {
			return;
		}

		await invoke('discovery_start');
		if (disposed) {
			invoke('discovery_stop').catch(() => {});
			return;
		}

		peers.value = (await invoke<Peer[]>('discovered_peers')) ?? [];
		await refreshPaired();
		syncDiscoveredPaired();
	} catch (error) {
		console.error('No se pudo iniciar el descubrimiento', error);
		// Si el arranque falló a mitad, soltar los oyentes que sí se registraron:
		// no dejarlos activos para un componente que no terminó de montar. `splice`
		// los saca de la lista para que el desmontaje no los suelte de nuevo.
		for (const un of unlistens.splice(0)) {
			un();
		}
	}
});

onUnmounted(() => {
	disposed = true;
	for (const un of unlistens) {
		un();
	}
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
        <StatusDot
          :tone="paired.length > 0 ? 'success' : 'neutral'"
          :label="paired.length > 0 ? t('inicio.estado.vinculado') : t('inicio.estado.sinVincular')" />
        <span class="text-tx-muted">
          {{ paired.length > 0 ? t('inicio.estado.vinculado') : t('inicio.estado.sinVincular') }}
        </span>
      </div>
    </section>

    <p
      v-if="result !== null"
      class="w-full max-w-sm rounded-corner-m px-4 py-3 text-center text-sm"
      :class="result.status === 'paired' ? 'text-status-success' : 'text-tx-muted'">
      {{ result.status === 'error' && result.message
        ? result.message
        : t(`inicio.resultado.${result.status}`) }}
    </p>

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
          class="flex items-center justify-between gap-3 rounded-corner-m bg-ui-surface/70 px-4 py-3 shadow-surface-s">
          <div class="flex min-w-0 flex-col">
            <span class="truncate font-medium text-tx-main">{{ peer.name }}</span>
            <span class="text-xs text-tx-muted">{{ t(`inicio.tipo.${peer.kind}`) }}</span>
          </div>
          <span
            v-if="pairedIds.has(peer.device_id)"
            class="shrink-0 text-sm text-status-success">
            {{ connected.includes(peer.device_id)
              ? t('inicio.descubiertos.conectado')
              : t('inicio.descubiertos.vinculado') }}
          </span>
          <button
            v-else
            type="button"
            class="shrink-0 rounded-corner-m bg-primary px-4 py-2 text-sm font-medium text-tx-on-primary transition-opacity hover:opacity-90 disabled:opacity-50"
            :disabled="pairing !== null"
            @click="pair(peer)">
            {{ t('inicio.descubiertos.vincular') }}
          </button>
        </li>
      </ul>
    </section>

    <!-- Diálogo del SAS: mientras hay un pareo en curso. -->
    <div
      v-if="pairing !== null"
      class="fixed inset-0 z-10 flex items-center justify-center bg-ui-bg/80 p-6">
      <div
        class="flex w-full max-w-sm flex-col items-center gap-4 rounded-corner-l bg-ui-surface p-6 shadow-surface-l">
        <h2 class="text-center text-lg font-medium text-tx-main">
          {{ t('inicio.sas.titulo') }}
        </h2>

        <p
          v-if="pairing.sas === null"
          class="py-4 text-center text-tx-muted">
          {{ t('inicio.sas.conectando') }}
        </p>

        <template v-else>
          <p class="text-center text-sm text-tx-muted">{{ t('inicio.sas.instruccion') }}</p>
          <p class="font-mono text-4xl tracking-widest text-tx-main">{{ pairing.sas }}</p>
          <div class="flex w-full gap-3">
            <button
              type="button"
              class="flex-1 rounded-corner-m bg-ui-surface px-4 py-2 text-sm font-medium text-tx-main shadow-surface-s transition-opacity hover:opacity-90"
              @click="confirm(false)">
              {{ t('inicio.sas.rechazar') }}
            </button>
            <button
              type="button"
              class="flex-1 rounded-corner-m bg-primary px-4 py-2 text-sm font-medium text-tx-on-primary transition-opacity hover:opacity-90"
              @click="confirm(true)">
              {{ t('inicio.sas.aceptar') }}
            </button>
          </div>
        </template>
      </div>
    </div>
  </main>
</template>
