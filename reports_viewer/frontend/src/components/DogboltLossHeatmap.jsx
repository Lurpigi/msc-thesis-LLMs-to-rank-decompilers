import React from "react";
import LossSection from "./LossSection";

/**
 * Main component: displays loss heatmaps for a dogbolt comparison item.
 * taskLossData contains: source_loss, source_ast_loss, <decompiler>_loss, <decompiler>_ast_loss
 * decompilerA and decompilerB are the decompiler names (e.g. "binary-ninja", "ghidra")
 */
export default function DogboltLossHeatmap({ taskLossData, decompilers }) {
  if (!taskLossData) return null;

  // Build sections dynamically based on available data
  const sections = [
    { key: "source_loss", title: "Source Code (Ground Truth)" },
    { key: "source_ast_loss", title: "AST — Source (Ground Truth)" },
  ];

  if (decompilers) {
      decompilers.forEach(d => {
          sections.push({ key: `${d}_loss`, title: `Decompiled — ${d}` });
          sections.push({ key: `${d}_ast_loss`, title: `AST — ${d}` });
      });
  }

  const availableSections = sections.filter(
    (s) =>
      taskLossData[s.key] &&
      taskLossData[s.key].tokens &&
      taskLossData[s.key].tokens.length > 0,
  );

  if (availableSections.length === 0) return null;

  return (
    <div className="space-y-3 mt-4">
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
          lossData={taskLossData[section.key]}
          defaultOpen={false}
        />
      ))}
    </div>
  );
}
