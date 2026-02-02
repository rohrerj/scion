import matplotlib.pyplot as plt
import numpy as np
import os

lengths = [100, 500, 1000, 5000]
impls = ["1", "2", "3"]

data = {}

# Load samples and trim to 95th percentile
for length in lengths:
    for impl in impls:
        fname = f"pkg/experimental/pot/monitor/Monitoring_{length}_num_infs_{impl}.txt"
        with open(fname) as f:
            samples = [int(line.strip()) for line in f if line.strip()]
        p95 = np.percentile(samples, 95)
        data[(length, impl)] = [s for s in samples if s <= p95]

fig, ax = plt.subplots(figsize=(9, 5))

group_width = 0.8
box_width = group_width / len(impls)

box_data = []
positions = []

# Build box_data and positions so each implementation is offset within each input length group
for i, length in enumerate(lengths):
    group_center = i + 1
    for j, impl in enumerate(impls):
        pos = group_center - group_width/2 + j*box_width + box_width/2
        positions.append(pos)
        box_data.append(data[(length, impl)])

# Plot all boxes
box_data_obj = np.empty(len(box_data), dtype=object)
box_data_obj[:] = box_data

ax.boxplot(
    box_data_obj,
    positions=positions,
    widths=box_width,
    showfliers=True,
)

# X-axis
ax.set_xticks(range(1, len(lengths) + 1))
ax.set_xticklabels([str(l) for l in lengths])
ax.set_xlabel("Input length")
ax.set_ylabel("Latency (ns)")
ax.set_title("Benchmark latency by input length and implementation")
ax.grid(axis="y", linestyle="--", alpha=0.4)

# Legend: manual trick
for j, impl in enumerate(impls):
    ax.plot([], [], label=f"impl {impl}")
ax.legend()

plt.tight_layout()
plt.show()