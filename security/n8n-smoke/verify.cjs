'use strict';
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
function validateOutput(text) {
  // Raw output can still include startup logs. Parse complete JSON suffixes,
  // never search for the expected numeric literal or trust CLI exit alone.
  const candidates = [...text.matchAll(/^\{/gm)].map(m => m.index);
  let result;
  for (const i of candidates) {
    try { result = JSON.parse(text.slice(i)); break; } catch {}
  }
  assert.ok(result, 'No complete execution JSON');
  assert.equal(result.finished, true);
  const data = result.data.resultData;
  assert.ok(!data.error, 'Execution error present');
  assert.equal(data.lastNodeExecuted, 'Benign Expression');
  assert.deepEqual(Object.keys(data.runData).sort(), ['Benign Expression', 'Manual Trigger']);
  const runs = data.runData['Benign Expression'];
  assert.equal(runs.length, 1);
  assert.ok(!runs[0].error);
  const items = runs[0].data.main[0];
  assert.equal(items.length, 1);
  assert.deepEqual(items[0].json, {answer: 42, marker: 'offline-fixture-only'});
}
module.exports = {validateOutput};
if (require.main === module) {
  assert.match(fs.readFileSync('/tmp/import.log', 'utf8'), /Successfully imported 1 workflow\./);
  const exported = JSON.parse(fs.readFileSync('/tmp/export.json', 'utf8'));
  assert.equal(exported.length, 1);
  assert.equal(exported[0].id, 'fixtureSmoke2384');
  assert.equal(exported[0].active, false);
  assert.equal(exported[0].nodes.length, 2);
  assert.ok(exported[0].nodes.every(n => !n.credentials));
  validateOutput(fs.readFileSync('/tmp/execution.log', 'utf8'));
  const db = new DatabaseSync('/home/node/.n8n/database.sqlite', {readOnly: true});
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM workflow_entity').get().n, 1);
  const row = db.prepare('SELECT id, active FROM workflow_entity').get();
  assert.equal(row.id, 'fixtureSmoke2384');
  assert.equal(row.active, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM credentials_entity').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM user WHERE email IS NOT NULL OR password IS NOT NULL').get().n, 0);
  db.close();
  console.log('PASS: version, CLI import/export, inactive fixture, benign expression=42, zero credentials and no configured account');
}
