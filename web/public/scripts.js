$(document).ready(function() {
    $('#analysis-form').on('submit', function(event) {
        event.preventDefault();
        const target = $('#target').val();
        const analysisType = $('#analysis-type').val();
        $.ajax({
            url: '/api/analyze',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ target: target, analysisType: analysisType }),
            success: function(data) {
                $('#results-output').empty();
                data.results.forEach(result => {
                    $('#results-output').append(`
                        <tr>
                            <td>${result.service}</td>
                            <td>${result.description}</td>
                            <td>${result.details}</td>
                        </tr>
                    `);
                });
            },
            error: function(error) {
                console.error('Error:', error);
            }
        });
    });

    $('#download-report').on('click', function() {
        const target = $('#target').val();
        const analysisType = $('#analysis-type').val();
        
        $.ajax({
            url: '/api/download-report',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ target: target, analysisType: analysisType }),
            success: function(data) {
                const blob = new Blob([data.report], { type: 'application/pdf' });
                const link = document.createElement('a');
                link.href = window.URL.createObjectURL(blob);
                link.download = 'informe.pdf';
                link.click();
            },
            error: function(error) {
                console.error('Error:', error);
            }
        });
    });
});
