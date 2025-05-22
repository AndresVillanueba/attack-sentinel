/* server.js – Plataforma de Análisis de Superficie de Ataque */
const express = require('express');
const path    = require('path');
const axios   = require('axios');
require('dotenv').config();

const app        = express();
const PORT       = process.env.PORT || 8080;
const CORTEX_URL = process.env.CORTEX_URL || 'http://cortex:9001';
const API_KEY    = process.env.CORTEX_API_KEY;

if (!API_KEY) {
  console.warn('⚠️  CORTEX_API_KEY no está definido; la web no podrá llamar a Cortex');
}

app.use(express.static(path.join(__dirname)));
app.use(express.json());

// Configuración de analizadores
const cfgMap = {
  attack_surface_scan: {
    name:  'attack_surface_scan', type: 'other', build: t => t.trim()
  },
  cve_lookup: {
    name:  'Vulners_CVE_1_0',      type: 'cve',   build: t => t.trim().toUpperCase()
  },
  subdomain_enum: {
    name:  'Crt_sh_Transparency_Logs_1_0', type: 'domain', build: t => t.trim().toLowerCase()
  },
  whois_lookup: {
    name:  'ThreatMiner_1_0',      type: t => (/^\d+\.\d+\.\d+\.\d+$/.test(t) ? 'ip' : 'domain'), build: t => t.trim()
  },
  technology_fingerprint: {
    name:  'VirusTotal_GetReport_3_1', type: 'url', build: t => /^https?:\/\//i.test(t) ? t.trim() : `http://${t.trim()}`
  },
  ipinfo_lookup: {
    name:  'IPinfo_Details_1_0',  type: t => 'ip', build: t => t.trim()
  }
};

// Helper para cabecera auth
const cortexReq = () => ({ headers: { Authorization: `Bearer ${API_KEY}` } });

// Resuelve ID de worker por nombre
async function resolveWorkerId(analyzerName) {
  const { data: list } = await axios.get(`${CORTEX_URL}/api/analyzer`, cortexReq());
  const it = list.find(a => a.name === analyzerName);
  return it ? it.id : null;
}

// Endpoint principal
app.post('/api/analyze', async (req, res) => {
  const { target, analysisType } = req.body;
  const cfg = cfgMap[analysisType];
  if (!cfg) return res.status(400).json({ error: 'Tipo de análisis no soportado' });

  try {
    // 1️⃣ Lanza job
    const dataType = typeof cfg.type === 'function' ? cfg.type(target) : cfg.type;
    const data     = cfg.build(target);
    const workerId = await resolveWorkerId(cfg.name);
    if (!workerId) return res.status(500).json({ error: `El analizador ${cfg.name} no existe en Cortex` });

    const { data: job } = await axios.post(
      `${CORTEX_URL}/api/analyzer/${workerId}/run`,
      { dataType, data },
      cortexReq()
    );

    // 2️⃣ Polling hasta Success
    let status = job.status;
    let report = null;
    while (['Waiting','InProgress'].includes(status)) {
      await new Promise(r => setTimeout(r, 1500));
      const { data: info } = await axios.get(`${CORTEX_URL}/api/job/${job.id}`, cortexReq());
      status = info.status;
      report = info.report || report;
    }
    if (status !== 'Success') return res.status(500).json({ error: `El job terminó en estado ${status}` });

    // 3️⃣ Obtener full si hace falta
    if (!report) {
      const { data: rep } = await axios.get(
        `${CORTEX_URL}/api/job/${job.id}/report`, cortexReq()
      );
      report = rep;
    }

    // 4️⃣ Construir rows según tipo de análisis
    let rows = [];
    if (cfg.name === 'Crt_sh_Transparency_Logs_1_0') {
      const certList = report.full.certobj?.result || report.certobj?.result || [];
      const subs = certList.flatMap(r => (r.name_value||'').split(/\s+/).filter(Boolean));
      rows = [...new Set(subs)].sort().map(name => ({ service: 'Subdomain', description: name, details: 'Detectado por crt.sh' }));

    } else if (report.summary?.taxonomies?.length) {
      rows = report.summary.taxonomies.map(t => ({ service: t.predicate, description: t.namespace, details: t.value }));

    } else if (cfg.name === 'IPinfo_Details_1_0') {
      // IPinfo devuelve summary.taxonomies con country, city, org, etc.
      rows = report.summary.taxonomies.map(t => ({ service: t.predicate, description: t.namespace, details: t.value }));

    } else if (Array.isArray(report.full?.exploits)) {
      rows = report.full.exploits.map(e => ({ service: 'Exploit', description: e.title, details: e.published || '' }));
    }

    if (!rows.length) rows = [{ service: '-', description: 'Sin resumen disponible', details: 'Revisa el informe completo en Cortex' }];

    // 5️⃣ Responder
    res.json({ results: rows, analyzer: cfg.name, full: report });
  }
  catch (err) {
    console.error('❌ Error en /api/analyze:', err.response?.data || err.message);
    res.status(500).json({ error: 'Error comunicándose con Cortex' });
  }
});

// Demo descarga PDF
app.post('/api/download-report', (_, res) => {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="informe.pdf"');
  res.send('Simulated PDF report content');
});

// Arranque
app.listen(PORT, () => console.log(`Web escuchando en http://localhost:${PORT}`));

