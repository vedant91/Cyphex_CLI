import matplotlib.pyplot as plt
import numpy as np
import os

# Set output directory to workspace
out_dir = r"D:\cyphex_v3\pitch_assets"
os.makedirs(out_dir, exist_ok=True)

# Clean, professional corporate style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.sans-serif'] = ['Segoe UI', 'Arial', 'sans-serif']
plt.rcParams['axes.edgecolor'] = '#ffffff'
plt.rcParams['axes.linewidth'] = 0
plt.rcParams['axes.labelcolor'] = '#333333'
plt.rcParams['text.color'] = '#333333'
plt.rcParams['xtick.color'] = '#666666'
plt.rcParams['ytick.color'] = '#666666'

# Colors
cyphex_color = '#00C853'  # Professional Green
ghas_color = '#2979FF'    # Corporate Blue
snyk_color = '#FF1744'    # Alert Red

# ---------------------------------------------------------
# GRAPH 1: False Positive Triage Time (Hours/Week for team of 20)
# ---------------------------------------------------------
plt.figure(figsize=(9, 5))
tools = ['Enterprise SAST\n(Manual Triage)', 'GitHub Adv. Security\n(Manual Triage)', 'CYPHEX v4.3\n(AI Council Debate)']
hours = [35, 25, 1.5]
colors = [snyk_color, ghas_color, cyphex_color]

bars = plt.barh(tools, hours, color=colors, height=0.6)
plt.title('Developer Hours Wasted on False Positives (Per Week)', fontsize=16, pad=20, weight='bold')
plt.xlabel('Hours per week', fontsize=12)

# Add value labels
for bar in bars:
    width = bar.get_width()
    plt.text(width + 0.5, bar.get_y() + bar.get_height()/2, f'{width} hrs', 
             ha='left', va='center', fontsize=11, weight='bold')

plt.xlim(0, 40)
plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'graph1_triage_time.png'), dpi=300, bbox_inches='tight')
plt.close()

# ---------------------------------------------------------
# GRAPH 2: TCO (Total Cost of Ownership) Over 3 Years
# ---------------------------------------------------------
plt.figure(figsize=(9, 5))
years = ['Year 1', 'Year 2', 'Year 3']
# Assuming 50 developers
snyk_cost = [100000, 200000, 300000]
ghas_cost = [29400, 58800, 88200]  # 49 * 50 * 12
cyphex_cost = [0, 0, 0]

plt.plot(years, snyk_cost, marker='o', linewidth=3, color=snyk_color, label='Enterprise SAST ($100k/yr)')
plt.plot(years, ghas_cost, marker='o', linewidth=3, color=ghas_color, label='GitHub Security ($49/user/mo)')
plt.plot(years, cyphex_cost, marker='o', linewidth=3, color=cyphex_color, label='CYPHEX v4.3 (Free/Offline)')

# Fill area under CYPHEX just for visual flair
plt.fill_between(years, cyphex_cost, color=cyphex_color, alpha=0.1)

plt.title('Total Cost of Ownership (3-Year Projection for 50 Devs)', fontsize=16, pad=20, weight='bold')
plt.ylabel('Cumulative Cost (USD)', fontsize=12)
plt.legend(fontsize=11, loc='upper left')
plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda x, loc: "${:,}".format(int(x))))
plt.ylim(-10000, 350000)

plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'graph2_tco.png'), dpi=300, bbox_inches='tight')
plt.close()

# ---------------------------------------------------------
# GRAPH 3: Autonomous Capabilities Matrix
# ---------------------------------------------------------
plt.figure(figsize=(10, 6))
categories = ['Static Analysis\n(SAST)', 'Live Attacker\nSimulation (DAST)', 'Zero-Day\nImmune System', 'AI Patch\nGeneration', '100% Offline\nExecution']

cyphex_scores = [1, 1, 1, 1, 1]
ghas_scores = [1, 0, 0, 0, 0]
snyk_scores = [1, 0, 0, 0, 0]

x = np.arange(len(categories))
width = 0.25

plt.bar(x - width, snyk_scores, width, label='Enterprise SAST', color=snyk_color, alpha=0.8)
plt.bar(x, ghas_scores, width, label='GitHub Adv. Security', color=ghas_color, alpha=0.9)
plt.bar(x + width, cyphex_scores, width, label='CYPHEX v4.3', color=cyphex_color)

plt.title('Feature Completeness & Autonomous Capabilities', fontsize=16, pad=20, weight='bold')
plt.xticks(x, categories, fontsize=11)
plt.yticks([0, 1], ['No', 'Yes'], fontsize=12)
plt.legend(fontsize=11, loc='upper right', bbox_to_anchor=(1, 0.9))

plt.tight_layout()
plt.savefig(os.path.join(out_dir, 'graph3_capabilities.png'), dpi=300, bbox_inches='tight')
plt.close()

print("Graphs generated successfully.")
