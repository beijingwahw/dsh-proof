// Throwaway probes for the Node adapter fidelity work (deleted after use).
// P1: does a self-SIGTERM child surface as a signal in the parent on Windows?
// P2: bare name that only resolves to a .cmd in PATH — async error or sync throw?
// P3: explicit <path>.cmd without shell — sync throw EINVAL or async error?
import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SCRATCH = fileURLToPath(new URL('./', import.meta.url))

const c1 = spawn(process.execPath, ['-e', "process.kill(process.pid,'SIGTERM')"])
c1.on('error', (e) => { console.log('P1 error ' + e.code); p2() })
c1.on('close', (code, sig) => {
  console.log(`P1 close code=${code} signal=${JSON.stringify(sig)} signalCode=${JSON.stringify(c1.signalCode)}`)
  p2()
})

function p2() {
  const dir = join(SCRATCH, 'probe-bin')
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'dshprobecmd.cmd'), 'totally not a real shim\n')
  const env = { ...process.env }
  const key = Object.keys(env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH'
  env[key] = dir + ';' + (env[key] ?? '')
  let c2
  try {
    c2 = spawn('dshprobecmd', ['x'], { env, shell: false })
  } catch (e) {
    console.log('P2 SYNC THROW: ' + e.message)
    return p3(dir)
  }
  c2.on('error', (e) => { console.log('P2 error event: ' + e.code); p3(dir) })
  c2.on('close', (code) => { console.log('P2 close code=' + code); p3(dir) })
}

function p3(dir) {
  try {
    const c3 = spawn(join(dir, 'dshprobecmd.cmd'), ['x'], { shell: false })
    c3.on('error', (e) => console.log('P3 error event: ' + e.code))
    c3.on('close', (code) => console.log('P3 close code=' + code))
  } catch (e) {
    console.log('P3 SYNC THROW: ' + e.message)
  }
}
