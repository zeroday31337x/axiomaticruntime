import test from 'node:test';
import assert from 'node:assert/strict';
import { features, featureNames, predict, validateArtifact } from '../linear-model.mjs';
const weights = [Array(8).fill(0), Array(8).fill(0), Array(8).fill(0)];
const artifact = { schemaVersion: '1', classes: ['ALLOW','DENY','FLAG'], featureNames: [...featureNames], weights };
test('valid artifact is accepted', () => assert.equal(validateArtifact(artifact), true));
test('malformed artifacts fail closed', () => {
  assert.equal(predict({ route: '/health', method: 'GET' }, { ...artifact, weights: [[Infinity]] }).decision, 'FLAG');
});
test('uncertain predictions flag', () => assert.equal(predict({ route: '/health', method: 'GET' }, artifact).decision, 'FLAG'));
test('suspicious routes are represented', () => assert.equal(features({ route: '/../admin', method: 'GET' })[7], 1));
test('missing route fails closed', () => assert.equal(predict({ method: 'GET' }, artifact).decision, 'FLAG'));
