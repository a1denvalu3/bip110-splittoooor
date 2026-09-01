// Harness: canonicalStringify collision / confusion tests (server.ts:766-775 == App.tsx:1951-1960)
const canonicalStringify = (obj: any): string => {
    const keys = Object.keys(obj).sort();
    const sortedObj: Record<string, any> = {};
    for (const key of keys) {
        if (obj[key] !== undefined) {
            sortedObj[key] = obj[key];
        }
    }
    return JSON.stringify(sortedObj);
};

const pairs: [string, any, any][] = [
    ['undefined drop', { status: 'X', extra: undefined }, { status: 'X' }],
    ['-0 vs 0', { lockTime: -0 }, { lockTime: 0 }],
    ['1 vs 1.0', { lockTime: 1 }, { lockTime: 1.0 }],
    ['quote injection in key', { 'a":1,"b': 2 }, { a: 1, b: 2 }],
    ['__proto__ own key', JSON.parse('{"__proto__":{"polluted":1},"status":"X"}'), { status: 'X' }],
    ['nested order', { s: { b: 1, a: 2 } }, { s: { a: 2, b: 1 } }],
    ['array vs object', { v: [1, 2] }, { v: { 0: 1, 1: 2 } }],
    ['string vs number', { lockTime: '500' }, { lockTime: 500 }],
    ['int-like key order', { 10: 'a', 2: 'b', x: 1 }, { x: 1, 2: 'b', 10: 'a' }],
];

for (const [name, a, b] of pairs) {
    const sa = canonicalStringify(a), sb = canonicalStringify(b);
    console.log(`${sa === sb ? 'COLLIDE' : 'diff   '} | ${name} | A=${sa} | B=${sb}`);
}

// Does the __proto__ payload survive into the signed message?
const protoFields = JSON.parse('{"__proto__":{"polluted":1},"status":"FUNDED_INITIATOR"}');
console.log('\n__proto__ canonical:', canonicalStringify(protoFields));
console.log('proto own keys:', Object.keys(protoFields));
// Would the DB layer apply it? allowedKeys loop reads fields[key] only for whitelisted keys — check:
const allowed = ['status', 'acceptorPubKey', 'lockTime'];
const applied: any = {};
for (const k of allowed) if (protoFields[k] !== undefined) applied[k] = protoFields[k];
console.log('DB-applied fields:', applied, '| global prototype polluted?', ({} as any).polluted);
