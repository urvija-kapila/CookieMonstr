import test from 'node:test';
import assert from 'node:assert/strict';
import { COOKIE_RULES } from '../lib/cookieRules.js';
const cookie = (overrides = {}) => ({ name: 'preferences', domain: 'example.com', secure: true, httpOnly: true, sameSite: 'lax', ...overrides });
const fires = (id, data) => COOKIE_RULES.find(rule => rule.id === id).test(data);
test('each cookie rule has a distinct ID', () => {
 const ids = COOKIE_RULES.map(rule => rule.id);
 assert.equal(ids.length, new Set(ids).size);
});
test('missing HttpOnly is detected', () => {
 assert.equal(fires('missing_httponly', cookie({httpOnly:false})), true);
 assert.equal(fires('missing_httponly', cookie()), false);
});
test('missing Secure is detected for named session cookie', () => {
 assert.equal(fires('missing_secure', cookie({ name:'session_id',secure:false })), true);
 assert.equal(fires('missing_secure', cookie({ name:'session_id' })), false);
});
test('unspecified SameSite is detected', () => {
 assert.equal(fires('samesite_missing', cookie({sameSite:'unspecified'})), true);
 assert.equal(fires('samesite_missing', cookie()), false);
});
test('SameSite None without Secure is detected', () => {
 assert.equal(fires('samesite_none_without_secure', cookie({sameSite:'no_restriction',secure:false})), true);
 assert.equal(fires('samesite_none_without_secure', cookie({sameSite:'no_restriction'})), false);
});
test('broad cookie domain is detected', () => {
 assert.equal(fires('broad_domain', cookie({domain:'.example.com'})), true);
 assert.equal(fires('broad_domain', cookie()), false);
});
test('long-lived authentication cookie is detected', () => {
 assert.equal(fires('long_lived_session', cookie({name:'session_id',expirationDate:Date.now()/1000+200*86400})), true);
 assert.equal(fires('long_lived_session', cookie({name:'session_id',expirationDate:Date.now()/1000+30*86400})), false);
});
