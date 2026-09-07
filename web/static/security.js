(() => {
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  async function request(action, body) {
    const csrf = document.querySelector('input[name="gorilla.csrf.Token"]')?.value;
    const response = await fetch('/account/passkeys/' + action, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf || ''}, body:JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not complete this security step.');
    return result;
  }
  document.querySelectorAll('[data-passkey]').forEach(button => button.addEventListener('click', async () => {
    const status = document.getElementById('passkey-status');
    const message = text => {if (status) status.textContent = text;};
    if (!window.PublicKeyCredential || !window.isSecureContext) {message('Passkeys require a supported browser and HTTPS. Use your authenticator or recovery code instead.');return;}
    if (/^[0-9.]+$/.test(location.hostname) || location.hostname.includes(':')) {message('Open Waypoint using its configured hostname to use passkeys. An IP address cannot be used as a passkey domain.');return;}
    button.disabled = true;
    try {
      const register = button.dataset.passkey === 'register';
      const name = document.getElementById('passkey-name')?.value.trim();
      if (register && !name) throw new Error('Give your passkey a name first.');
      message('Follow the prompt from your browser or device.');
      const options = await request(register ? 'register-begin' : 'login-begin', {name});
      const pk = options.publicKey;
      pk.challenge = decode(pk.challenge);
      if (pk.user) pk.user.id = decode(pk.user.id);
      for (const field of ['allowCredentials','excludeCredentials']) if (pk[field]) pk[field].forEach(c => c.id = decode(c.id));
      const credential = register ? await navigator.credentials.create({publicKey:pk}) : await navigator.credentials.get({publicKey:pk});
      const response = {clientDataJSON:encode(credential.response.clientDataJSON)};
      if (register) {response.attestationObject = encode(credential.response.attestationObject);response.transports = credential.response.getTransports?.() || [];}
      else {response.authenticatorData = encode(credential.response.authenticatorData);response.signature = encode(credential.response.signature);response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;}
      const result = await request(register ? 'register-finish' : 'login-finish', {id:credential.id,rawId:encode(credential.rawId),type:credential.type,response,clientExtensionResults:credential.getClientExtensionResults(),authenticatorAttachment:credential.authenticatorAttachment});
      if (result.codes?.length) {
        message('Passkey added. Save these recovery codes now; they appear only once.');
        const target = document.getElementById('passkey-codes');target.replaceChildren();
        const list = document.createElement('div');list.id='recovery-codes';list.className='recovery-codes';
        result.codes.forEach(code=>{const el=document.createElement('code');el.textContent=code;list.append(el);});target.append(list);
        const download=document.createElement('button');download.textContent='Download recovery codes';download.dataset.downloadCodes='';target.append(download);
        const link=document.createElement('a');link.href='/account/security';link.textContent='I’ve saved my codes — continue';target.append(link);link.focus();
      } else window.location.assign(result.redirect);
    } catch (error) {message(error.name === 'NotAllowedError' ? 'The passkey prompt was cancelled or timed out. You can try again.' : error.message);}
    finally {button.disabled = false;}
  }));
  document.addEventListener('click', event => {
    if (!event.target.closest('[data-download-codes]')) return;
    const codes=Array.from(document.querySelectorAll('#recovery-codes code')).map(el=>el.textContent);
    const url=URL.createObjectURL(new Blob(['Waypoint recovery codes\nStore privately. Each works once and resets login methods.\n\n'+codes.join('\n')],{type:'text/plain'}));
    const a=document.createElement('a');a.href=url;a.download='waypoint-recovery-codes.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
})();
