export type Entry = {
    site: string;
    username: string;
    password: string;
};
export type WeakFinding = {
    index: number;
    site: string;
    username: string;
    reasons: string[];
};
export type ReuseGroup = {
    count: number;
    sites: {
        site: string;
        username: string;
    }[];
};
export type Report = {
    summary: {
        total: number;
        weak: number;
        reusedGroups: number;
        reusedAccounts: number;
    };
    weakFindings: WeakFinding[];
    reuseGroups: ReuseGroup[];
};
export declare function analyze(entries: Entry[]): Report;
//# sourceMappingURL=index.d.ts.map