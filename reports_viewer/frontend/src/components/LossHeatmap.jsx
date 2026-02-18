import React, { useState, useMemo } from "react";
import clsx from "clsx";

/**
 * Renders a single token with background color based on its loss.
 * Uses a gradient from transparent (low loss) to red (high loss).
 */
function TokenSpan({ token, loss, maxLoss }) {
  const intensity = Math.min(loss / 8.0, 1.0);

  // Gradient: low loss = cool blue/green, high loss = warm red
  let bg;
  if (intensity < 0.25) {
    bg = `rgba(69, 140, 246, ${intensity * 0.6 > 0.03 ? intensity * 0.6 : 0.03})`; // blue
  } else if (intensity < 0.5) {
    bg = `rgba(234, 179, 8, ${intensity * 0.7})`; // yellow
  } else if (intensity < 0.75) {
    bg = `rgba(249, 115, 22, ${intensity * 0.8})`; // orange
  } else {
    bg = `rgba(239, 68, 68, ${intensity * 0.9})`; // red
  }

  // Clean token: remove Ġ (GPT-style space prefix) and handle newlines
  const cleanToken = token
    .replace(/Ġ/g, " ")
    .replace(/Ċ/g, "\n")
    .replace(/ĉ/g, "\t");

  const isNewline = cleanToken.includes("\n");

  return (
    <>
      <span
        className="inline rounded-sm cursor-default transition-all duration-150 hover:ring-2 hover:ring-indigo-400 hover:z-10 relative"
        style={{
          backgroundColor: bg,
          padding: "1px 0px",
          fontSize: "0.8rem",
          lineHeight: "1.6",
        }}
        title={`Token: "${token}" | Loss: ${loss.toFixed(4)}`}
      >
        {isNewline
          ? cleanToken.split("\n").map((part, i, arr) => (
              <React.Fragment key={i}>
                {part}
                {i < arr.length - 1 && <br />}
              </React.Fragment>
            ))
          : cleanToken}
      </span>
    </>
  );
}

/**
 * A collapsible section displaying tokens colored by loss.
 */
function LossSection({ title, lossData, defaultOpen = false }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  if (!lossData || !lossData.tokens || !lossData.losses) return null;
  if (lossData.tokens.length === 0) return null;

  const { tokens, losses } = lossData;

  const stats = useMemo(() => {
    const mean = losses.reduce((a, b) => a + b, 0) / losses.length;
    const max = Math.max(...losses);
    const min = Math.min(...losses);
    const median = [...losses].sort((a, b) => a - b)[
      Math.floor(losses.length / 2)
    ];
    return { mean, max, min, median, count: tokens.length };
  }, [losses, tokens]);

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-gray-50 hover:bg-gray-100 transition-colors duration-150 text-left"
      >
        <div className="flex items-center gap-3">
          <svg
            className={clsx(
              "w-4 h-4 text-gray-500 transition-transform duration-200",
              isOpen && "rotate-90",
            )}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 5l7 7-7 7"
            />
          </svg>
          <span className="text-sm font-semibold text-gray-700">{title}</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-gray-500">
          <span>
            Tokens:{" "}
            <span className="font-mono font-bold text-gray-700">
              {stats.count}
            </span>
          </span>
          <span>
            Mean Loss:{" "}
            <span className="font-mono font-bold text-gray-700">
              {stats.mean.toFixed(3)}
            </span>
          </span>
          <span>
            Max:{" "}
            <span className="font-mono font-bold text-red-600">
              {stats.max.toFixed(3)}
            </span>
          </span>
          <span>
            Min:{" "}
            <span className="font-mono font-bold text-green-600">
              {stats.min.toFixed(3)}
            </span>
          </span>
        </div>
      </button>

      {isOpen && (
        <div className="px-4 py-3 bg-white">
          {/* Legend */}
          <div className="flex items-center gap-2 mb-3 text-[10px] text-gray-500">
            <span>Loss:</span>
            <div className="flex items-center gap-0.5">
              <span
                className="inline-block w-4 h-3 rounded-sm"
                style={{ backgroundColor: "rgba(59, 130, 246, 0.15)" }}
              />
              <span>Low</span>
            </div>
            <div className="flex items-center gap-0.5">
              <span
                className="inline-block w-4 h-3 rounded-sm"
                style={{ backgroundColor: "rgba(234, 179, 8, 0.35)" }}
              />
              <span>Med</span>
            </div>
            <div className="flex items-center gap-0.5">
              <span
                className="inline-block w-4 h-3 rounded-sm"
                style={{ backgroundColor: "rgba(249, 115, 22, 0.6)" }}
              />
              <span>High</span>
            </div>
            <div className="flex items-center gap-0.5">
              <span
                className="inline-block w-4 h-3 rounded-sm"
                style={{ backgroundColor: "rgba(239, 68, 68, 0.9)" }}
              />
              <span>Very High</span>
            </div>
            <span className="ml-2 text-gray-400">
              (hover tokens for exact values)
            </span>
          </div>

          {/* Token heatmap */}
          <div
            className="font-mono leading-relaxed whitespace-pre-wrap break-all p-3 rounded-md bg-gray-50 border border-gray-100 max-h-96 overflow-y-auto"
            style={{ tabSize: 4 }}
          >
            {tokens.map((token, i) => (
              <TokenSpan
                key={i}
                token={token}
                loss={losses[i]}
                maxLoss={stats.max}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Main component: displays loss heatmaps for a given function's metrics.
 * Shows: source, base (decompiled), PR (improved), and their AST variants.
 */
export default function LossHeatmap({ metrics }) {
  if (!metrics) return null;

  const sections = [
    {
      key: "source_loss",
      title: "Source Code (Ground Truth)",
      defaultOpen: false,
    },
    {
      key: "function_base_loss",
      title: "Decompiled — Base",
      defaultOpen: false,
    },
    {
      key: "function_pr_loss",
      title: "Decompiled — PR",
      defaultOpen: false,
    },
    {
      key: "source_ast_loss",
      title: "AST — Source (Ground Truth)",
      defaultOpen: false,
    },
    {
      key: "base_ast_loss",
      title: "AST — Base",
      defaultOpen: false,
    },
    {
      key: "pr_ast_loss",
      title: "AST — PR (Improved)",
      defaultOpen: false,
    },
  ];

  const availableSections = sections.filter(
    (s) =>
      metrics[s.key] &&
      metrics[s.key].tokens &&
      metrics[s.key].tokens.length > 0,
  );

  if (availableSections.length === 0) return null;

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-bold text-gray-500 uppercase tracking-wider flex items-center gap-2">
        <svg
          className="w-4 h-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
          />
        </svg>
        Token Loss Heatmap
      </h4>
      {availableSections.map((section) => (
        <LossSection
          key={section.key}
          title={section.title}
          lossData={metrics[section.key]}
          defaultOpen={section.defaultOpen}
        />
      ))}
    </div>
  );
}
