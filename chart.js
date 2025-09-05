const ctxBar = document.getElementById('categoryChart').getContext('2d');

// Function to determine bar color based on threat category
function getBarColorByCategory(category) {
    if (category.startsWith('Low')) return '#00e676'; // Vibrant Green
    if (category.startsWith('Medium')) return '#ffeb3b'; // Vibrant Yellow
    if (category.startsWith('High')) return '#ff3d00'; // Vibrant Orange-Red
    if (category.startsWith('Critical')) return '#d500f9'; // Vibrant Purple
    return '#90a4ae'; // Default Grey
}

// Bar chart initialization with glow effect plugin
let barChart = new Chart(ctxBar, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            label: 'Threat Scores',
            data: [],
            backgroundColor: [],
            borderColor: [],
            borderWidth: 1,
            hoverBackgroundColor: [],
            hoverBorderColor: []
            // categories field not needed here, handled in tooltip callback
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            easing: 'easeOutQuart',
            duration: 1200
        },
        scales: {
            x: {
                ticks: { color: '#ffffff' },
                grid: { display: false }
            },
            y: {
                beginAtZero: true,
                max: 100,
                ticks: { color: '#ffffff', stepSize: 10 },
                grid: { color: 'rgba(255,255,255,0.1)' }
            }
        },
        plugins: {
            legend: { labels: { color: '#ffffff' } },
            tooltip: {
                enabled: true,
                callbacks: {
                    label: function(context) {
                        const index = context.dataIndex;
                        const score = context.dataset.data[index];
                        const ip = context.chart.data.labels[index];
                        const category = context.chart.data.datasets[0].categories
                            ? context.chart.data.datasets[0].categories[index]
                            : 'N/A';
                        return [`IOC: ${ip}`, `Threat Score: ${score}`, `Category: ${category}`];
                    }
                }
            }
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        onHover: function(event, chartElements) {
            event.native.target.style.cursor = chartElements.length ? 'pointer' : 'default';
        }
    },
    plugins: [{
        id: 'glowOnHover',
        afterDraw: chart => {
            const ctx = chart.ctx;
            const points = chart.getDatasetMeta(0).data;
            points.forEach(point => {
                if (point.$context.hover) {
                    ctx.save();
                    ctx.shadowColor = point.options.backgroundColor;
                    ctx.shadowBlur = 15;
                    ctx.shadowOffsetX = 0;
                    ctx.shadowOffsetY = 0;
                    ctx.fillStyle = point.options.backgroundColor;
                    const x = point.x - point.width / 2;
                    const y = point.y;
                    const width = point.width;
                    const height = chart.scales.y.getPixelForValue(0) - point.y;
                    ctx.beginPath();
                    ctx.rect(x, y, width, height);
                    ctx.fill();
                    ctx.restore();
                }
            });
        }
    }]
});

// Create a canvas for the pie chart dynamically below the bar chart
const pieCanvas = document.createElement('canvas');
pieCanvas.id = 'categoryPieChart';
pieCanvas.style.height = '300px';
pieCanvas.style.marginTop = '40px';
ctxBar.canvas.parentNode.appendChild(pieCanvas);

const ctxPie = pieCanvas.getContext('2d');

// Pie chart for category distribution
let pieChart = new Chart(ctxPie, {
    type: 'pie',
    data: {
        labels: [],
        datasets: [{
            label: 'Category Distribution',
            data: [],
            backgroundColor: [
                '#e74c3c', // malware red
                '#f39c12', // phishing orange
                '#8e44ad', // botnet purple
                '#3498db', // exploit blue
                '#95a5a6'  // others gray
            ],
            borderColor: '#2c3e50',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            animateScale: true,
            animateRotate: true
        },
        plugins: {
            legend: { position: 'bottom', labels: { color: '#ffffff' } },
            tooltip: { enabled: true }
        }
    }
});

// Fetch latest threat data and update both charts
async function fetchThreatData() {
    try {
        const response = await fetch('/api/threat-data');
        const data = await response.json();

        if (response.ok) {
            // Update bar chart with live IOC labels and scores
            const labels = data.ips || [];
            const scores = data.scores || [];

            // Use categories from backend
            const categories = data.categories || Array(labels.length).fill("N/A");

            const backgroundColors = categories.map(category => getBarColorByCategory(category));

            barChart.data.labels = labels;
            barChart.data.datasets[0].data = scores;
            barChart.data.datasets[0].backgroundColor = backgroundColors;
            barChart.data.datasets[0].borderColor = backgroundColors;
            barChart.data.datasets[0].hoverBackgroundColor = backgroundColors;
            barChart.data.datasets[0].hoverBorderColor = backgroundColors;
            barChart.data.datasets[0].categories = categories; // Attach categories for tooltip

            barChart.update();

            // Fetch category counts dynamically from backend if available
            // Here we use a separate call or static example as placeholder:
            // Ideally your backend should return category counts like:
            // { malware: x, phishing: y, botnet: z, exploit: w, others: v }
            // You can create an endpoint or extend /api/threat-data to include this.

            // For demonstration, using static or mock data:
            const categoryCounts = {
                malware: 5,
                phishing: 3,
                botnet: 2,
                exploit: 1,
                others: 4
            };

            pieChart.data.labels = Object.keys(categoryCounts).map(c => c.charAt(0).toUpperCase() + c.slice(1));
            pieChart.data.datasets[0].data = Object.values(categoryCounts);
            pieChart.update();
        }
    } catch (error) {
        console.error('Error fetching threat data for charts:', error);
    }
}

// Initial fetch and refresh every 60 seconds
fetchThreatData();
setInterval(fetchThreatData, 60000);
