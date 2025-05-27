const express = require('express');
const path    = require('path');
const axios   = require('axios');
const { Client } = require('@opensearch-project/opensearch');
require('dotenv').config();

const app        = express();
const PORT       = process.env.PORT || 8080;
const CORTEX_URL = process.env.CORTEX_URL || 'http://localhost:9001';
const API_KEY    = process.env.CORTEX_API_KEY;
const OPENSEARCH_HOST = 'http://localhost:9200';
const INDEX_NAME = 'analisis';

/* Configuración Ollama  */
const OLLAMA_PORT  = process.env.OLLAMA_PORT  || 11434;   // puerto por defecto: 11434
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3'; 

/* Cliente OpenSearch */
const searchClient = new Client({ node: OPENSEARCH_HOST });

async function checkIndex () {
  try {
    const { body: exists } = await searchClient.indices.exists({ index: INDEX_NAME });
    if (!exists) {
      console.log('No se ha encontrado el índice, creando...');
      const { body: response } = await searchClient.indices.create({
        index: INDEX_NAME,
        body: {
          settings: {
            number_of_replicas: 1,
            number_of_shards:   1
          }
        }
      });
      return response;
    }
  } catch (error) {
    console.log('Error obteniendo datos de OpenSearch', error);
  }
}

if (!API_KEY) console.warn('CORTEX_API_KEY no está definido; la web no podrá llamar a Cortex');

app.use(express.static(path.join(__dirname)));
app.use(express.json());

/*  Mapa de analizadores disponibles */
const cfgMap = {
  attack_surface_scan: {
    name:  'SmapScan_1_0',
    type:  'other',
    build: t => t.trim()
  },
  cve_lookup: {
    name:  'Vulners_CVE_1_0',
    type:  'cve',
    build: t => t.trim().toUpperCase(),
    validate: txt => /^CVE-\d{4}-\d{4,}$/i.test(txt)
  },
  subdomain_enum: {
    name:  'Crt_sh_Transparency_Logs_1_0',
    type:  'domain',
    build: t => t.trim().toLowerCase()
  },
};

/* Utilidades Cortex */
const cortexHeaders = { Authorization: `Bearer ${API_KEY}` };

async function resolveWorkerId (analyzerName) {
  const { data } = await axios.get(`${CORTEX_URL}/api/analyzer`, { headers: cortexHeaders });
  const found = data.find(a => a.name === analyzerName);
  return found?.id ?? null;
}

/* Generación de informe */
/**
 * Envía el report bruto a Ollama para obtener un informe ejecutivo ultracorto (150 palabras).
 */
async function generateOllamaReport (report) {
  const url = `http://localhost:${OLLAMA_PORT}/api/generate`;
  const prompt =
    `Eres analista de ciberseguridad. Redacta un informe ejecutivo breve ` +
    `para un cliente no técnico, destacando riesgos clave, impacto y siguientes pasos. Datos de base:\n\n` +
    `${JSON.stringify(report, null, 2)}\n\nInforme resumido:`;

  const payload = { model: OLLAMA_MODEL, prompt, stream: false };
  try {
    const response = await axios({ method: 'post', url, data: payload, responseType: 'json' });
    return response.data.response || response.data;
  } catch (err) {
    console.error('Error llamando a Ollama', err.message);
    return 'No se pudo generar el informe AI';
  }
}

/*  endpoint /api/analyze */
async function saveReport (doc) {
  try {
    const res = await searchClient.index({ index: INDEX_NAME, body: doc, refresh: 'true' });
    return res;
  } catch (error) {
    console.log('Error añadiendo a OpenSearch');
  }
}

app.post('/api/analyze', async (req, res) => {
  await checkIndex();

  const { target, analysisType } = req.body;
  const cfg = cfgMap[analysisType];
  if (!cfg) return res.status(400).json({ error: 'Tipo de análisis no soportado' });
  if (cfg.validate && !cfg.validate(target))
    return res.status(400).json({ error: 'Formato incorrecto para este análisis' });

  try {
    /* Ejecutamos el analizador en Cortex */
    const dataType = typeof cfg.type === 'function' ? cfg.type(target) : cfg.type;
    const data     = cfg.build(target);
    const workerId = await resolveWorkerId(cfg.name);
    if (!workerId) throw new Error(`No existe el analizador ${cfg.name} en Cortex`);

    const { data: job } = await axios.post(
      `${CORTEX_URL}/api/analyzer/${workerId}/run`,
      { dataType, data },
      { headers: cortexHeaders }
    );

    /*Polling hasta que el job finalice */
    let status = job.status, report = null, tries = 0;
    while (['Waiting', 'InProgress'].includes(status) && tries < 30) {
      await new Promise(r => setTimeout(r, 2000));
      const { data: info } = await axios.get(`${CORTEX_URL}/api/job/${job.id}`, { headers: cortexHeaders });
      status = info.status;
      report = info.report || report;
      tries++;
    }
    if (status !== 'Success')
      return res.status(502).json({ error: `El job terminó en estado ${status}` });

    /*Si el report aún no está completo, lo solicitamos */
    if (!report) {
      const { data: rep } = await axios.get(`${CORTEX_URL}/api/job/${job.id}/report`, { headers: cortexHeaders });
      report = rep.report;
    }

    /*Generamos informe ultrarresumido con Ollama */
    const aiReport = await generateOllamaReport(report);
    console.log('Informe AI generado:', aiReport);

    /*Guardamos en OpenSearch */
    const doc = {
      timestamp: new Date().toISOString(),
      target,
      analyzer: analysisType,
      result: report,
      aiReport: aiReport
    };
    await saveReport(doc);

    /*Resumen tabular para la UI */
    let rows = [];
    if (cfg.name === 'Crt_sh_Transparency_Logs_1_0') {
      const certList = report.full?.certobj?.result || report.certobj?.result || [];
      const subs = [...new Set(certList.flatMap(r => (r.name_value || '').split(/\s+/)).filter(Boolean))];
      rows = subs.map(name => ({ service: 'Subdomain', description: name, details: 'Detectado por crt.sh' }));
    } else if (Array.isArray(report.summary?.taxonomies)) {
      rows = report.summary.taxonomies.map(t => ({ service: t.predicate, description: t.namespace, details: t.value }));
    } else if (Array.isArray(report.full?.exploits)) {
      rows = report.full.exploits.map(e => ({ service: 'Exploit', description: e.title, details: e.published ?? '' }));
    }
    if (!rows.length) rows = [{ service: '-', description: 'Sin resumen disponible', details: 'Revisa el informe completo en Cortex' }];

    return res.json({ analyzer: cfg.name, results: rows, full: report, aiReport: aiReport });
  } catch (err) {
    const detail = err.response?.data?.message || err.message || 'Error desconocido';
    console.error('/api/analyze:', detail);
    res.status(500).json({ error: 'Error comunicándose con Cortex', detail });
  }
});

/* descarga PDF  */
app.post('/api/download-report', (_, res) => {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="informe.pdf"');
  res.send('Simulated PDF report content');
});

/*  start server */
app.listen(PORT, () => console.log(`Web escuchando en http://localhost:${PORT}`));