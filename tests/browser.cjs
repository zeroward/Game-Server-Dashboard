'use strict';
const { chromium } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { randomBytes, createHmac } = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const base = 'http://localhost:8088';
const password = randomBytes(24).toString('hex');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'waypoint-e2e-'));
const server = spawn(process.env.E2E_SERVER || '/testserver', [], { env: { ...process.env, E2E_DATA_DIR: directory, E2E_PASSWORD: password }, stdio: ['ignore', 'ignore', 'pipe'] });
let errors = ''; server.stderr.on('data', b => { errors += b.toString(); });
const results = [];
async function check(name, fn) { await fn(); results.push(name); console.log(`PASS ${name}`); }
function totpCode(secret) {
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of secret.replace(/=/g,''))bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2)));const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
 const mac=createHmac('sha1',key).update(counter).digest();const offset=mac[19]&15;return ((mac.readUInt32BE(offset)&0x7fffffff)%1000000).toString().padStart(6,'0');
}
async function login(page, username) {
  await page.goto(base + '/account/login');
  await page.getByLabel('Username', { exact: true }).fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  if (new URL(page.url()).pathname === '/account/security') {
    await page.getByRole('button', {name:'Set up authenticator',exact:true}).click();
    const secret=await page.locator('#totp-secret').innerText();
    await page.getByLabel('Authenticator code',{exact:true}).fill(totpCode(secret));
    await page.getByRole('button',{name:'Confirm authenticator',exact:true}).click();
    await page.getByRole('heading',{name:'Save your recovery codes'}).waitFor();
    await page.goto(base+'/');
  }
  if (new URL(page.url()).pathname !== '/') { await page.screenshot({path:'/work/test-results/login-failure.png'}); throw new Error('Login failed: ' + await page.locator('#main').innerText()); }
}
async function a11y(page, name) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  if (results.violations.length) await page.screenshot({path:'/work/test-results/a11y-failure.png',fullPage:true});
  assert.equal(results.violations.length, 0, `${name}: ${JSON.stringify(results.violations.map(v => ({id:v.id, nodes:v.nodes.map(n=>n.target)})))}`);
}
(async () => {
  let browser;
  try {
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(base + '/healthz')).ok) break; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
      if (i === 99) throw new Error('Test server failed: ' + errors);
    }
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    const owner = await browser.newContext({ viewport: { width: 1440, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
    const page = await owner.newPage();
    const pageErrors = []; page.on('pageerror', e => pageErrors.push(e.message));
    fs.mkdirSync('/work/test-results', { recursive: true });
    await check('login page accessibility', async () => { await page.goto(base + '/account/login'); await a11y(page, 'login'); });
    await login(page, 'test-owner');
    await check('desktop artwork catalog and accessibility', async () => {
      assert.equal(await page.locator('.service-card').count(), 4);
      await a11y(page, 'catalog');
      await page.screenshot({ path: '/work/test-results/catalog-desktop.png', fullPage: true });
    });
    await check('search and category filters', async () => {
      await page.getByRole('searchbox').count();
      await page.getByLabel('Search services').fill('Plex');
      await page.getByRole('button', { name: 'Search', exact: true }).click();
      assert.equal(await page.locator('.service-card').count(), 1);
      await page.goto(base + '/');
      await page.getByRole('navigation', { name: 'Categories' }).getByRole('link', { name: 'Development' }).click();
      assert.equal(await page.locator('.service-card').count(), 1);
    });
    await check('canonical details, back navigation and copy feedback', async () => {
      await page.goto(base + '/services/campfire');
      await page.reload();
      await page.getByRole('button', { name: 'Copy connection string' }).click();
      await page.getByRole('status').filter({ hasText: 'Copied to clipboard.' }).waitFor();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'game.example.invalid:25565');
      await a11y(page, 'service');
      await page.getByRole('link', { name: 'Back to library' }).click();
      await page.goBack();
      assert.ok(page.url().endsWith('/services/campfire'));
    });
    await check('admin editor preview and saved ordering', async () => {
      await page.goto(base + '/admin/services/1');
      await page.getByLabel('Display name', { exact: true }).fill('World of Warcraft');
      await page.getByLabel('Short description', { exact: true }).fill('An evening in Azeroth, with friends.');
      assert.equal(await page.locator('#preview-summary').textContent(), 'An evening in Azeroth, with friends.');
      await page.getByRole('button', { name: 'Save service', exact: true }).click();
      await page.getByRole('status').filter({ hasText: 'Saved' }).waitFor();
      await a11y(page, 'service editor');
    });
    const member = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const friend = await member.newPage();
    await check('invite and single-use account redemption', async () => {
      await page.goto(base + '/admin/members');
      await page.getByLabel('Reserved username').fill('test-friend');
      await page.getByRole('button', { name: 'Create invitation link' }).click();
      const link = await page.getByLabel('Single-use link').inputValue();
      await friend.goto(link);
      await friend.getByText('Your username: test-friend', {exact:true}).waitFor();
      await friend.getByLabel('New password', { exact: true }).fill(password);
      await friend.getByRole('button', { name: 'Set password' }).click();
      await friend.waitForURL(/account\/login/);
      assert.equal(await friend.getByLabel('Username', {exact:true}).inputValue(), 'test-friend');
      await login(friend, 'test-friend');
    });
    let requestURL;
    await check('development request keeps restricted instructions private', async () => {
      await friend.goto(base + '/services/development-network');
      assert.equal(await friend.getByRole('heading', { name: 'Connection details stay private.' }).count(), 1);
      assert.equal(await friend.getByText('Wait for the administrator’s separate enrollment instructions.').count(), 0);
      await friend.getByLabel('Reason', { exact: true }).fill('A personal development experiment');
      await friend.getByLabel('Device name').fill('My laptop');
      await friend.getByLabel('Intended use').fill('Learning Go');
      await friend.getByRole('button', { name: 'Send access request' }).click();
      await friend.waitForURL(/\/requests\/\d+$/); requestURL = friend.url();
      await a11y(friend, 'request');
    });
    await check('private notes, questions and member-visible replies', async () => {
      await page.goto(requestURL);
      await page.getByLabel('Private administrator note', { exact: true }).fill('INTERNAL_BROWSER_SENTINEL');
      await page.getByRole('button', { name: 'Save private note' }).click();
      await page.getByLabel('Next state').selectOption('Needs Information');
      await page.getByLabel('Member-visible explanation').fill('Which operating system?');
      page.once('dialog', d => d.accept());
      await page.getByRole('button', { name: 'Update request' }).click();
      await friend.reload();
      assert.equal((await friend.content()).includes('INTERNAL_BROWSER_SENTINEL'), false);
      await friend.getByLabel('Member-visible reply').fill('Linux');
      await friend.getByRole('button', { name: 'Send reply' }).click();
      await friend.getByText('Linux', { exact: true }).waitFor();
    });
    await check('approval does not unlock; fulfillment creates usable My Access', async () => {
      await page.goto(requestURL);
      await page.getByLabel('Next state').selectOption('Approved - Setup Pending');
      page.once('dialog', d => d.accept());
      await page.getByRole('button', { name: 'Update request' }).click();
      await friend.goto(base + '/services/development-network');
      assert.equal(await friend.getByRole('heading', { name: 'Connection details stay private.' }).count(), 1);
      await page.getByLabel('Next state').selectOption('Fulfilled');
      await page.getByLabel('Non-secret next steps', { exact: true }).fill('Follow your separately delivered enrollment instructions.');
      await page.getByLabel('I performed the external setup.').check();
      page.once('dialog', d => d.accept());
      await page.getByRole('button', { name: 'Update request' }).click();
      await friend.goto(base + '/my-access');
      await friend.getByText('Follow your separately delivered enrollment instructions.', { exact: true }).waitFor();
      await friend.getByRole('link', { name: 'Setup & details' }).click();
      await friend.getByRole('heading', { name: 'Help me connect', exact: true }).waitFor();
      assert.equal(await friend.getByRole('button', { name: 'Send access request' }).count(), 0);
      await friend.screenshot({ path: '/work/test-results/service-fulfilled.png', fullPage: true });
    });
    await check('device enrollment and explicit network approval', async () => {
      await page.goto(base + '/admin/vpn');
      await page.getByText('Add a destination', {exact:true}).click();
      const targetForm = page.locator('form').filter({has:page.getByRole('button',{name:'Add destination',exact:true})});
      await targetForm.getByLabel('Associated service').selectOption({label:'Development Network'});
      await targetForm.getByLabel('Member-visible label').fill('Workspace HTTPS');
      await targetForm.getByLabel('IPv4 destination/CIDR').fill('192.0.2.42/32');
      await targetForm.getByLabel('Ports or ranges').fill('443');
      await targetForm.getByRole('button',{name:'Add destination',exact:true}).click();
      await friend.goto(base + '/my-devices');
      await friend.getByText('Advanced: use your own public key',{exact:true}).click();
      await friend.getByLabel('Advanced device name', {exact:true}).fill('Browser test laptop');
      await friend.getByLabel('WireGuard public key',{exact:true}).fill(randomBytes(32).toString('base64'));
      await friend.getByRole('button',{name:'Add device',exact:true}).click();
      await friend.getByText('Request another connection',{exact:true}).click();
      await friend.getByLabel('Intended use',{exact:true}).fill('Work on a small project');
      await friend.getByRole('button',{name:'Request network access',exact:true}).click();
      assert.equal((await friend.content()).includes('192.0.2.42'), false);
      await page.reload();
      const decision = page.locator('form').filter({has:page.getByRole('button',{name:'Save decision',exact:true})});
      await decision.getByLabel('Expiry date', {exact:false}).fill(new Date(Date.now()+3*86400000).toISOString().slice(0,10));
      await decision.getByLabel("I reviewed this device's public key",{exact:false}).check();
      await decision.getByLabel('Member-visible explanation',{exact:true}).fill('Workspace HTTPS approved for this laptop.');
      page.once('dialog',d=>d.accept());
      await decision.getByRole('button',{name:'Save decision',exact:true}).click();
      await friend.reload();
      assert.ok((await friend.content()).includes('192.0.2.42/32'));
      await friend.getByText('Set up this device',{exact:true}).click();
      if (errors.includes('template error')) throw new Error(errors);
      assert.equal(await friend.getByLabel('AllowedIPs',{exact:true}).inputValue(),'192.0.2.42/32');
      await a11y(friend,'device setup desktop');
      await friend.locator('h1').click();
      await friend.screenshot({path:'/work/test-results/devices-desktop.png',fullPage:true});
      await a11y(page,'network administration');
    });
    await check('mobile device setup and confirmed revocation request', async () => {
      await friend.setViewportSize({width:390,height:844});
      assert.equal(await friend.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await a11y(friend,'device setup mobile');
      await friend.locator('h1').click();
      await friend.screenshot({path:'/work/test-results/devices-mobile.png',fullPage:true});
      await friend.getByText('Revoke this device',{exact:true}).click();
      await friend.getByLabel('I want to revoke all network permissions for this device.').check();
      friend.once('dialog',d=>d.accept());
      await friend.getByRole('button',{name:'Revoke device',exact:true}).click();
      assert.equal((await friend.content()).includes('192.0.2.42'),false);
      await friend.goto(base+'/notifications');
      assert.ok(await friend.locator('a[href*=device-]').count()>0);
    });
    await check('automatic one-time connection pack and replacement', async () => {
      await friend.setViewportSize({width:1440,height:1000});
      await friend.goto(base+'/my-devices');
      await friend.getByLabel('Device name',{exact:true}).fill('Easy laptop');
      await friend.getByLabel('What would you like to use it for?',{exact:true}).fill('Connect to my workspace');
      await friend.getByRole('button',{name:'Add device & request connection',exact:true}).click();
      const device=friend.locator('article.device').filter({has:friend.getByRole('heading',{name:'Easy laptop',exact:true})});
      await device.getByRole('heading',{name:'Waiting for approval'}).waitFor();
      assert.equal(await device.getByRole('button',{name:'Download connection pack'}).count(),0);
      await page.goto(base+'/admin/vpn');
      const decision=page.locator('form').filter({has:page.getByRole('button',{name:'Save decision',exact:true})});
      await decision.getByLabel('Expiry date',{exact:false}).fill(new Date(Date.now()+3*86400000).toISOString().slice(0,10));
      await decision.getByLabel("I reviewed this device's public key",{exact:false}).check();
      await decision.getByLabel('Member-visible explanation',{exact:true}).fill('Ready to connect.');
      page.once('dialog',d=>d.accept());
      await decision.getByRole('button',{name:'Save decision',exact:true}).click();
      for(let i=0;i<20;i++){await friend.reload();if(await device.getByRole('button',{name:'Download connection pack'}).count())break;await friend.waitForTimeout(150);}
      await a11y(friend,'automatic connection pack desktop');
      await friend.locator('h1').click();
      await friend.screenshot({path:'/work/test-results/pack-desktop.png',fullPage:true});
      await friend.setViewportSize({width:390,height:844});
      assert.equal(await friend.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await a11y(friend,'automatic connection pack mobile');
      await friend.locator('h1').click();
      await friend.screenshot({path:'/work/test-results/pack-mobile.png',fullPage:true});
      const downloadPromise=friend.waitForEvent('download');
      await device.getByRole('button',{name:'Download connection pack'}).click();
      const download=await downloadPromise;
      assert.match(download.suggestedFilename(),/^waypoint-device-\d+\.zip$/);
      const downloadedPath=await download.path();
      const pack=fs.readFileSync(downloadedPath);
      assert.equal(pack.readUInt32LE(0),0x04034b50);
      const secret=pack.toString('utf8').match(/PrivateKey = ([A-Za-z0-9+/=]{44})/)[1];
      assert.ok(pack.includes(Buffer.from('AllowedIPs = 192.0.2.42/32')));
      assert.ok(pack.includes(Buffer.from('READ-ME.txt')));
      await download.delete();
      await friend.reload();
      await device.getByRole('heading',{name:'Connection pack downloaded'}).waitFor();
      assert.equal((await friend.content()).includes(secret),false);
      assert.equal(await device.getByRole('button',{name:'Download connection pack'}).count(),0);
      await device.getByText('Replace connection pack',{exact:true}).click();
      await device.getByLabel('Reason for replacement',{exact:true}).fill('Lost my connection pack');
      await device.getByLabel('Retire this connection and request approval for a new pack.').check();
      friend.once('dialog',d=>d.accept());
      await device.getByRole('button',{name:'Request replacement',exact:true}).click();
      await friend.getByRole('heading',{name:'Waiting for approval',exact:true}).waitFor();
      assert.equal(await friend.getByRole('button',{name:'Download connection pack'}).count(),0);
    });
    await check('mobile layout, keyboard navigation and accessibility' , async () => {
      await friend.setViewportSize({ width: 390, height: 844 });
      await friend.goto(base + '/');
      assert.equal(await friend.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await a11y(friend, 'mobile catalog');
      await friend.keyboard.press('Tab');
      assert.notEqual(await friend.evaluate(() => document.activeElement.tagName), 'BODY');
      await friend.locator('h1').click();
      await friend.screenshot({ path: '/work/test-results/catalog-mobile.png', fullPage: true });
      await friend.goto(base + '/my-access');
      assert.equal(await friend.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    });
    await check('passkey enrollment, direct login and required user verification', async () => {
      await page.goto(base+'/account/security');
      const cdp=await owner.newCDPSession(page);await cdp.send('WebAuthn.enable');
      const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
      await page.getByLabel('Passkey name').fill('Browser test passkey');await page.getByRole('button',{name:'Add a passkey',exact:true}).click();
      try { await page.getByText('Browser test passkey',{exact:true}).waitFor({timeout:10000}); } catch(e) { throw new Error('Passkey enrollment: '+await page.locator('#passkey-status').innerText()); }
      await a11y(page,'account security desktop');await page.screenshot({path:'/work/test-results/security-desktop.png',fullPage:true});
      await page.setViewportSize({width:390,height:844});await a11y(page,'account security mobile');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'/work/test-results/security-mobile.png',fullPage:true});await page.setViewportSize({width:1440,height:1000});
      await page.locator('#main').getByRole('button',{name:'Sign out',exact:true}).click();
      await cdp.send('WebAuthn.setUserVerified',{authenticatorId,isUserVerified:false});
      await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();
      await page.locator('#passkey-status').filter({hasText:/failed|cancelled|timed out/}).waitFor();assert.ok(page.url().includes('/account/login'));
      await cdp.send('WebAuthn.setUserVerified',{authenticatorId,isUserVerified:true});
      await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();await page.waitForURL(base+'/');
      await page.goto(base+'/admin/email');await a11y(page,'email administration');
      await page.goto(base+'/account/security');
      await page.route('**/account/passkeys/login-finish',async route=>{
        const body=route.request().postDataJSON();const client=JSON.parse(Buffer.from(body.response.clientDataJSON,'base64url').toString());client.origin='https://attacker.invalid';body.response.clientDataJSON=Buffer.from(JSON.stringify(client)).toString('base64url');await route.continue({postData:JSON.stringify(body)});
      });
      await page.getByRole('button',{name:'Sign out',exact:true}).last().click();
      await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();await page.locator('#passkey-status').filter({hasText:/failed/}).waitFor();
      assert.ok(page.url().includes('/account/login'));await page.unroute('**/account/passkeys/login-finish');
      await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();await page.waitForURL(base+'/');

    });
    await check('passkey-only onboarding, recovery-code delivery and no password bypass',async()=>{
      await page.goto(base+'/admin/members');await page.getByLabel('Reserved username').fill('passkey-friend');await page.getByRole('button',{name:'Create invitation link',exact:true}).click();const invitation=await page.getByLabel('Single-use link').inputValue();
      const context=await browser.newContext();const newcomer=await context.newPage();await newcomer.goto(invitation);await newcomer.getByLabel('New password',{exact:true}).fill(password);await newcomer.getByRole('button',{name:'Set password',exact:true}).click();
      await newcomer.getByLabel('Username',{exact:true}).fill('passkey-friend');await newcomer.getByLabel('Password',{exact:true}).fill(password);await newcomer.getByRole('button',{name:'Sign in',exact:true}).click();
      const cdp=await context.newCDPSession(newcomer);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
      await newcomer.getByLabel('Passkey name').fill('My laptop');await newcomer.getByRole('button',{name:'Add a passkey',exact:true}).click();await newcomer.getByRole('link',{name:'I’ve saved my codes — continue'}).waitFor();assert.equal(await newcomer.locator('#recovery-codes code').count(),10);await newcomer.getByRole('link',{name:'I’ve saved my codes — continue'}).click();
      await newcomer.locator('#main').getByRole('button',{name:'Sign out',exact:true}).click();await newcomer.getByLabel('Username',{exact:true}).fill('passkey-friend');await newcomer.getByLabel('Password',{exact:true}).fill(password);await newcomer.getByRole('button',{name:'Sign in',exact:true}).click();await newcomer.getByText('This account uses passkeys.',{exact:false}).waitFor();
      await newcomer.goto(base+'/admin');assert.equal(await newcomer.getByText('YOUR COMMUNITY, THOUGHTFULLY MANAGED',{exact:true}).count(),0);
      await context.close();
    });
    await check('no browser JavaScript errors', async () => assert.deepEqual(pageErrors, []));
    fs.writeFileSync('/work/test-results/browser-results.json', JSON.stringify({ passed: results }, null, 2));
    console.log(`${results.length} browser scenarios passed.`);
  } finally {
    if (browser) await browser.close();
    server.kill('SIGTERM');
    fs.rmSync(directory, { recursive: true, force: true });
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
