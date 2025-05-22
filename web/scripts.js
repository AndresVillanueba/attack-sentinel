/* ------- scripts.js ▸ lógica del front ------- */
$(function () {
  const $form    = $('#analysis-form');
  const $results = $('#results');
  const $tbody   = $('#results-output');
  const $full    = $('#full-report');
  const $dl      = $('#download-report');

  /* ───────── submit ───────── */
  $form.on('submit', function (e) {
    e.preventDefault();

    const target = $('#target').val().trim();
    const type   = $('#analysis-type').val();
    if (!target) return alert('Debes indicar IP o dominio');

    /* reset UI */
    $tbody.empty();
    $full.text('');
    $results.hide();

    $.ajax({
      url: '/api/analyze',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ target, analysisType: type })
    })
    .done(function (data) {
      /* ----------- resumen ------------- */
      if (Array.isArray(data.results) && data.results.length) {
        data.results.forEach(r => {
          $('<tr>')
            .append($('<td>').text(r.service))
            .append($('<td>').text(r.description))
            .append($('<td>').text(r.details))
            .appendTo($tbody);
        });
      } else {
        $('<tr>')
          .append($('<td>').text('-'))
          .append($('<td>').text('Sin resumen disponible'))
          .append($('<td>').text('Revisa el informe completo en Cortex'))
          .appendTo($tbody);
      }

      /* ----------- informe completo ------------- */
      $full.text(JSON.stringify(data.full, null, 2));
      $results.show();
    })
    .fail(xhr => {
      console.error(xhr.responseText);
      alert('Error al comunicar con Cortex');
    });
  });

  /* ───────── descarga “PDF” de demo ───────── */
  $dl.on('click', function () {
    fetch('/api/download-report', { method: 'POST' })
      .then(res => res.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob);
        $('<a>')
          .attr({ href: url, download: 'informe.pdf' })
          .appendTo('body')[0].click();
        URL.revokeObjectURL(url);
      });
  });
});

