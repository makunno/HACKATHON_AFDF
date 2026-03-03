"""HTML interactive map generator"""
import json
from pathlib import Path
from typing import List, Dict


class HTMLMapGenerator:
    """
    Generate interactive HTML entropy maps.
    """
    
    def __init__(self):
        pass
    
    def generate(
        self,
        blocks: List[Dict],
        regions: List[Dict],
        output_path: Path,
        title: str = "EntropyGuard Analysis"
    ) -> Path:
        """
        Generate interactive HTML entropy map.
        
        Args:
            blocks: List of block dictionaries
            regions: List of suspicious regions
            output_path: Output HTML file path
            title: Page title
            
        Returns:
            Path to generated HTML
        """
        # Prepare data for JavaScript
        entropy_data = []
        for block in blocks:
            entropy_data.append({
                "offset": block.get("offset", 0),
                "entropy": block.get("shannon_entropy", 0),
                "score": block.get("anomaly_score", 0),
                "anomalous": block.get("is_anomalous", False)
            })
        
        # HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            color: #00ff88;
            margin-bottom: 20px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #0f3460;
        }}
        .stat-card h3 {{
            color: #00ff88;
            font-size: 14px;
            margin-bottom: 5px;
        }}
        .stat-card .value {{
            font-size: 24px;
            font-weight: bold;
        }}
        .visualization {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .entropy-bar {{
            height: 30px;
            background: #0f3460;
            position: relative;
            margin: 5px 0;
            cursor: pointer;
        }}
        .entropy-bar:hover {{
            background: #1a4a7a;
        }}
        .bar-segment {{
            position: absolute;
            height: 100%;
            transition: opacity 0.2s;
        }}
        .regions {{
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
        }}
        .region {{
            background: #0f3460;
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid #ff6b6b;
        }}
        .region h4 {{
            color: #ff6b6b;
            margin-bottom: 8px;
        }}
        .region .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            font-size: 14px;
        }}
        .legend {{
            display: flex;
            gap: 20px;
            margin: 15px 0;
            flex-wrap: wrap;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }}
        .tooltip {{
            position: fixed;
            background: #000;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            pointer-events: none;
            display: none;
            z-index: 1000;
            border: 1px solid #00ff88;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>EntropyGuard - Interactive Entropy Map</h1>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Blocks</h3>
                <div class="value">{len(entropy_data):,}</div>
            </div>
            <div class="stat-card">
                <h3>Anomalous Blocks</h3>
                <div class="value" style="color: #ff6b6b;">{sum(1 for b in entropy_data if b.get('anomalous')):,}</div>
            </div>
            <div class="stat-card">
                <h3>Suspicious Regions</h3>
                <div class="value" style="color: #ff6b6b;">{len(regions)}</div>
            </div>
            <div class="stat-card">
                <h3>Max Entropy</h3>
                <div class="value" style="color: #00ff88;">{max((b.get('entropy', 0) for b in entropy_data), default=0):.4f}</div>
            </div>
        </div>
        
        <div class="visualization">
            <h2 style="margin-bottom: 15px;">Entropy Distribution</h2>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #0000ff;"></div>
                    <span>Low Entropy (0-2)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #00ff00;"></div>
                    <span>Medium (2-5)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffff00;"></div>
                    <span>High (5-7)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff0000;"></div>
                    <span>Very High (7-8)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff00ff; border: 2px solid #fff;"></div>
                    <span>Anomalous</span>
                </div>
            </div>
            <div id="entropy-vis"></div>
        </div>
        
        <div class="regions">
            <h2 style="margin-bottom: 15px;">Suspicious Regions</h2>
            <div id="regions-list"></div>
        </div>
    </div>
    
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        const entropyData = {json.dumps(entropy_data)};
        const regionsData = {json.dumps(regions)};
        const blockSize = {blocks[0].get('size', 4096) if blocks else 4096};
        
        function getEntropyColor(entropy) {{
            if (entropy < 2) return 'rgb(0, 0, 255)';
            if (entropy < 5) return 'rgb(0, ' + Math.floor(255 * (entropy - 2) / 3) + ', 0)';
            if (entropy < 7) return 'rgb(255, ' + Math.floor(255 * (7 - entropy) / 2) + ', 0)';
            return 'rgb(255, 0, 0)';
        }}
        
        // Render entropy visualization
        const vis = document.getElementById('entropy-vis');
        const segmentWidth = Math.max(1, Math.floor(entropyData.length / 2000));
        
        for (let i = 0; i < entropyData.length; i += segmentWidth) {{
            const segment = entropyData.slice(i, i + segmentWidth);
            const avgEntropy = segment.reduce((a, b) => a + b.entropy, 0) / segment.length;
            const hasAnomaly = segment.some(b => b.anomalous);
            
            const bar = document.createElement('div');
            bar.className = 'entropy-bar';
            bar.style.left = (i / entropyData.length * 100) + '%';
            bar.style.width = (segmentWidth / entropyData.length * 100) + '%';
            bar.style.backgroundColor = getEntropyColor(avgEntropy);
            
            if (hasAnomaly) {{
                bar.style.border = '2px solid #ff00ff';
            }}
            
            bar.addEventListener('mouseenter', (e) => {{
                const tooltip = document.getElementById('tooltip');
                tooltip.style.display = 'block';
                tooltip.style.left = e.pageX + 10 + 'px';
                tooltip.style.top = e.pageY + 10 + 'px';
                tooltip.innerHTML = `
                    Offset: ${{segment[0].offset.toLocaleString()}}<br>
                    Entropy: ${{avgEntropy.toFixed(4)}}<br>
                    Anomaly Score: ${{segment.reduce((a,b)=>a+b.score,0)/segment.length.toFixed(1)}}
                `;
            }});
            
            bar.addEventListener('mouseleave', () => {{
                document.getElementById('tooltip').style.display = 'none';
            }});
            
            vis.appendChild(bar);
        }}
        
        // Render regions
        const regionsList = document.getElementById('regions-list');
        if (regionsData.length === 0) {{
            regionsList.innerHTML = '<p>No suspicious regions detected.</p>';
        }} else {{
            regionsData.forEach((region, idx) => {{
                const div = document.createElement('div');
                div.className = 'region';
                div.innerHTML = `
                    <h4>Region ${{idx + 1}} - Score: ${{region.mean_anomaly_score.toFixed(1)}}</h4>
                    <div class="meta">
                        <div><strong>Start:</strong> 0x${{region.start_offset.toString(16).toUpperCase()}}</div>
                        <div><strong>End:</strong> 0x${{region.end_offset.toString(16).toUpperCase()}}</div>
                        <div><strong>Size:</strong> ${{region.size.toLocaleString()}} bytes</div>
                        <div><strong>Blocks:</strong> ${{region.block_count}}</div>
                        <div><strong>Mean Entropy:</strong> ${{region.mean_entropy.toFixed(4)}}</div>
                        <div><strong>Max Entropy:</strong> ${{region.max_entropy.toFixed(4)}}</div>
                    </div>
                `;
                regionsList.appendChild(div);
            }});
        }}
    </script>
</body>
</html>"""
        
        output_path.write_text(html, encoding="utf-8")
        return output_path
