/* scripts.js – cliente jQuery revisado */
$(function () {
  //   Para proxy inverso o distinto dominio: const API_BASE = 'https://midominio.com';
  const API_BASE = '';

  // Cachés de elementos
  const $form   = $('#analysis-form');
  const $table  = $('#results-table');
  const $tbody  = $('#results-output');
  const $full   = $('#full-report');
  const $wrap   = $('#results');
  const $btnPDF = $('#download-report');

  /*  Lanzar análisis  */
  $form.submit(async function (e) {
    e.preventDefault();

    const target       = $('#target').val().trim();
    const analysisType = $('#analysis-type').val();

    // Reset UI
    $wrap.hide();
    $tbody.empty();
    $full.empty();
    $btnPDF.hide();

    try {
      /*Llamada al backend */
      const resp = await $.ajax({
        url:  `${API_BASE}/api/analyze`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ target, analysisType })
      });

      /* Pintar tabla*/
      resp.results.forEach(r => {
        $tbody.append(`
          <tr>
            <td>${r.service}</td>
            <td>${r.description}</td>
            <td>${r.details}</td>
          </tr>
        `);
      });

      // Compacta si hay muchas filas
      $table.toggleClass('table-sm', resp.results.length > 5);

      /*Informe completo */
      $full.text(resp.aiReport || 'No se generó informe AI');

      /* Mostrar resultados */
      $wrap.fadeIn();
      $btnPDF.show();

    } catch (xhr) {
      // xhr puede ser jqXHR o error
      const msg = xhr.responseJSON?.error || xhr.statusText || xhr.message || 'Error desconocido';
      alert(`Error al ejecutar el análisis:\n${msg}`);
      console.error('POST /api/analyze →', xhr);
    }
  });

  /*  Descargar PDF demo */
  $btnPDF.click(() => {
    window.location = `${API_BASE}/api/download-report`;
  });
});

