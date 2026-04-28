import { Card } from "@/shared/ui/card";

export function StatsCards({ stats }: { stats: Array<{ label: string; value: string | number }> }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-3">
      {stats.map((stat) => (
        <Card key={stat.label}>
          <p className="text-sm text-slate-500 dark:text-slate-400">{stat.label}</p>
          <p className="mt-2 text-2xl font-semibold">{stat.value}</p>
        </Card>
      ))}
    </div>
  );
}
