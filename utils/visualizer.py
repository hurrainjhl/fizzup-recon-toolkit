import base64
import io
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.figure import Figure
from typing import Dict, List, Tuple, Optional

class DataVisualizer:
    """
    Creates professional visualizations for reconnaissance data
    Supports multiple output formats: PNG, SVG, HTML embeds
    """
    def __init__(self, style: str = "whitegrid", palette: str = "muted"):
        self.style = style
        self.palette = palette
        sns.set_theme(style=style, palette=palette)
    
    def generate_bar_chart(self, data: Dict, title: str, 
                          xlabel: str, ylabel: str) -> Figure:
        """
        Generate bar chart from dictionary data
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        keys = list(data.keys())
        values = list(data.values())
        
        # Sort if numeric values
        if all(isinstance(v, (int, float)) for v in values):
            sorted_indices = sorted(range(len(values)), key=lambda i: values[i], reverse=True)
            keys = [keys[i] for i in sorted_indices]
            values = [values[i] for i in sorted_indices]
        
        barplot = sns.barplot(x=keys, y=values, ax=ax)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for i, v in enumerate(values):
            ax.text(i, v + 0.01 * max(values), str(v), 
                   ha='center', va='bottom', fontsize=9)
        
        fig.tight_layout()
        return fig
    
    def generate_pie_chart(self, data: Dict, title: str) -> Figure:
        """
        Generate pie chart from dictionary data
        """
        fig, ax = plt.subplots(figsize=(8, 8))
        keys = list(data.keys())
        values = list(data.values())
        
        # Sort by value
        sorted_indices = sorted(range(len(values)), key=lambda i: values[i], reverse=True)
        keys = [keys[i] for i in sorted_indices]
        values = [values[i] for i in sorted_indices]
        
        # Auto-explode small slices
        explode = [0.1 if v/sum(values) < 0.05 else 0 for v in values]
        
        wedges, texts, autotexts = ax.pie(
            values, 
            labels=keys, 
            autopct='%1.1f%%',
            startangle=90,
            explode=explode,
            pctdistance=0.85
        )
        
        # Improve label appearance
        plt.setp(autotexts, size=10, weight="bold", color="white")
        plt.setp(texts, size=10)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.axis('equal')  # Equal aspect ratio ensures pie is circular
        return fig
    
    def generate_timeline(self, data: Dict, title: str, 
                         xlabel: str = "Time", ylabel: str = "Count") -> Figure:
        """
        Generate timeline chart from timestamped data
        """
        fig, ax = plt.subplots(figsize=(12, 6))
        timestamps = sorted(data.keys())
        values = [data[ts] for ts in timestamps]
        
        ax.plot(timestamps, values, marker='o', linestyle='-')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.grid(True, linestyle='--', alpha=0.7)
        fig.autofmt_xdate()
        return fig
    
    def generate_heatmap(self, data: List[List], row_labels: List, 
                        col_labels: List, title: str) -> Figure:
        """
        Generate annotated heatmap from 2D data
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(
            data, 
            annot=True, 
            fmt="d", 
            cmap="YlGnBu",
            ax=ax,
            xticklabels=col_labels,
            yticklabels=row_labels
        )
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel("")
        ax.set_ylabel("")
        return fig
    
    def save_figure(self, fig: Figure, filename: str, dpi: int = 300):
        """Save figure to file"""
        fig.savefig(filename, bbox_inches='tight', dpi=dpi)
        plt.close(fig)
    
    def figure_to_base64(self, fig: Figure, format: str = "png") -> str:
        """Convert figure to base64 encoded string"""
        buf = io.BytesIO()
        fig.savefig(buf, format=format, bbox_inches='tight')
        buf.seek(0)
        img_str = base64.b64encode(buf.read()).decode()
        return f"data:image/{format};base64,{img_str}"
    
    def generate_report_ready_image(self, fig: Figure) -> str:
        """Generate image optimized for HTML reports"""
        return self.figure_to_base64(fig, "svg")  # SVG for crisp resolution
    
    def close_all(self):
        """Close all figures and release memory"""
        plt.close('all')

# Example usage
if __name__ == "__main__":
    visualizer = DataVisualizer()
    
    # Bar chart example
    port_data = {"80": 45, "443": 78, "22": 32, "8080": 12}
    bar_fig = visualizer.generate_bar_chart(
        port_data, 
        "Open Port Distribution", 
        "Port Number", 
        "Count"
    )
    visualizer.save_figure(bar_fig, "ports.png")
    
    # Pie chart example
    tech_data = {"Apache": 35, "Nginx": 25, "IIS": 15, "Other": 25}
    pie_fig = visualizer.generate_pie_chart(tech_data, "Web Server Technologies")
    pie_base64 = visualizer.figure_to_base64(pie_fig)
    
    # Timeline example
    from datetime import datetime, timedelta
    timeline_data = {
        (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d"): i*10
        for i in range(1, 8)
    }
    timeline_fig = visualizer.generate_timeline(
        timeline_data, 
        "Domain Registration Timeline"
    )
    
    # Heatmap example
    heatmap_data = [[12, 15, 8], [7, 9, 11], [5, 14, 10]]
    heatmap_fig = visualizer.generate_heatmap(
        heatmap_data,
        ["Critical", "High", "Medium"],
        ["SQLi", "XSS", "RCE"],
        "Vulnerability Distribution"
    )
    
    visualizer.close_all()
    print("Visualization examples generated successfully")
