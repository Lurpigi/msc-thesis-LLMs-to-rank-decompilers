import React from "react";
import LossSection from "./LossSection";

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
      title: "AST — PR",
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
