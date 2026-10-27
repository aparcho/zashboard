// 使用真实 Python 服务和 SQLite 的桌面/窄屏浏览器验收，不访问线上 Nikki。
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { sleep, waitFor } from './lib/cdp.mjs'
import { startHarness } from './lib/harness.mjs'
import { findFreePort } from './lib/ports.mjs'

const temp = await mkdtemp(join(tmpdir(), 'zashboard-stats-ui-'))
const token = randomBytes(32).toString('hex')
const port = await findFreePort()
const base = `http://127.0.0.1:${port}`
let harness, child, mock
let checks = 0
const check = (condition, label) => {
  assert.ok(condition, label)
  console.log(`✓ ${label}`)
  checks++
}
try {
  harness = await startHarness({ groups: 3, nodes: 3, connections: 3, appUrl: base })
  const fixture = harness.mock.activeConnections
  let tick = 0
  mock = createServer((req, res) => {
    const body =
      req.url === '/rules'
        ? { rules: [] }
        : {
            uploadTotal: ++tick * 300,
            downloadTotal: tick * 3000,
            connections: fixture.map((c, i) => ({
              ...c,
              upload: tick * 100,
              download: tick * 1000,
              metadata: { ...c.metadata, sourceIP: i === 2 ? '2001:db8::10' : '192.168.1.2' },
            })),
          }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  })
  await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve))
  const config = {
    source_id: 'test-source',
    controller_label: '本地验收模拟源',
    controller: `http://127.0.0.1:${mock.address().port}`,
    api_token: token,
    interval: 0.2,
    port,
    listen: '127.0.0.1',
    database: join(temp, 'stats.sqlite3'),
    static_dir: join(process.cwd(), 'dist'),
    allowed_origins: [harness.app.url],
  }
  await writeFile(join(temp, 'config.json'), JSON.stringify(config))
  child = spawn(
    process.env.PYTHON_BIN || 'python3',
    ['stats-service/service.py', '--config', join(temp, 'config.json')],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  )
  let serviceLog = ''
  child.stderr.on('data', (data) => (serviceLog += data.toString()))
  const request = async (path, body) => {
    const response = await fetch(`${base}/api/stats/${path}`, {
      method: body ? 'PUT' : 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    })
    assert.equal(response.status, 200, await response.clone().text())
    return response.json()
  }
  const ready = await waitFor(
    async () => {
      try {
        return (await request('status')).healthy
      } catch {
        return false
      }
    },
    { timeout: 10000 },
  )
  check(ready !== null, `真实采集服务启动 ${serviceLog}`)
  const page = await harness.openProxiesPage({ settings: { 'config/language': 'zh-CN' } })
  try {
    check(
      (await waitFor(() =>
        page.evaluate(
          `document.querySelector('[data-traffic-group]')?.getAttribute('title')?.includes('下载')`,
        ),
      )) !== null,
      '全新浏览器无需令牌和设置，自动加载卡片累计',
    )
    check(
      await page.evaluate(
        `!document.body.innerText.includes('启用累计统计') && !document.querySelector('.modal-open input[type="password"]')`,
      ),
      '不显示启用按钮或令牌弹层',
    )
    check(
      await page.evaluate(
        `(() => { const b=document.querySelector('[data-traffic-group]'); const name=document.querySelector('[data-group-name] .collapse-motion-header'); return !!b && !!name && b.getBoundingClientRect().top < name.getBoundingClientRect().top + 32 })()`,
      ),
      '累计位于标题行，不新增卡片行',
    )
    const groupData = await request('group-totals')
    check(
      groupData.rows.some((row) => row.name === harness.mock.groupNames[0] && row.download > 0),
      '多层组累计来自真实 SQLite 数据',
    )
    const expandedBefore = await page.evaluate(
      `document.querySelectorAll('.collapse-motion-open').length`,
    )
    await page.evaluate(`document.querySelector('[data-traffic-group]').click()`)
    check(
      (await waitFor(() =>
        page.evaluate(`document.querySelector('.modal-open')?.innerText.includes('开始累计')`),
      )) !== null,
      '点击累计值打开组用量详情',
    )
    check(
      (await page.evaluate(`document.querySelectorAll('.collapse-motion-open').length`)) ===
        expandedBefore,
      '统计详情不触发原卡片展开',
    )
    await page.evaluate(`document.querySelector('.modal-open button[aria-label="close"]').click()`)
    await page.reload()
    check(
      (await waitFor(() =>
        page.evaluate(
          `document.querySelector('[data-traffic-group]')?.getAttribute('title')?.includes('下载')`,
        ),
      )) !== null,
      '刷新后仍免设置自动加载累计',
    )
    await page.screenshot(join(temp, 'proxy-cards.png'))
    await page.call('Emulation.setDeviceMetricsOverride', {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    })
    check(
      (await waitFor(() =>
        page.evaluate(
          `document.querySelector('[data-traffic-group]')?.getAttribute('title')?.includes('下载')`,
        ),
      )) !== null,
      '移动端标题行自动显示累计',
    )
    check(
      await page.evaluate(
        `(() => { const b=document.querySelector('[data-traffic-group]'); const card=b?.closest('[data-group-name]'); return !!b && !!card && b.getBoundingClientRect().bottom <= card.getBoundingClientRect().bottom && document.documentElement.scrollWidth <= innerWidth })()`,
      ),
      '移动端双列标题累计没有被裁切或横向溢出',
    )
    await page.screenshot(join(temp, 'proxy-cards-mobile.png'))
    await page.call('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    })
    await page.goto(`${harness.app.url}/#/traffic-stats`)
    await waitFor(() =>
      page.evaluate(`location.hash.includes('traffic-stats') && !!document.querySelector('h1')`),
    )
    await page.reload()
    const connected = await waitFor(
      () => page.evaluate(`document.body?.innerText.includes('采集中')`),
      { timeout: 15000 },
    )
    if (connected === null)
      console.log(
        await page.evaluate(`JSON.stringify({hash:location.hash, text:document.body?.innerText})`),
      )
    check(connected !== null, '统计页面连接真实采集服务')
    check(
      await page.evaluate(`document.body?.innerText.includes('未绑定设备')`),
      '未绑定设备流量正确展示',
    )
    const clickText = async (text) => {
      const clicked = await page.evaluate(
        `(() => { const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}); if(!b) return false; b.click(); return true })()`,
      )
      assert.ok(clicked, `按钮不存在: ${text}`)
    }
    const fill = async (selector, value) =>
      page.evaluate(
        `(() => { const el=document.querySelector(${JSON.stringify(selector)}); if(!el) throw Error('表单不存在'); el.value=${JSON.stringify(value)}; el.dispatchEvent(new Event('input',{bubbles:true})); })()`,
      )
    await clickText('设备绑定')
    await fill('input[placeholder="例如：MacBook"]', '验收 Mac')
    await fill('textarea', '192.168.1.2\n2001:db8::10')
    await clickText('保存设备')
    check(
      (await waitFor(
        () =>
          page.evaluate(
            `document.body?.innerText.includes('验收 Mac') && document.querySelector('button.btn-primary')?.disabled === false`,
          ),
        { timeout: 10000 },
      )) !== null,
      '通过页面保存双栈设备绑定',
    )
    const devices = await request('devices')
    check(devices[0]?.ips.length === 2, '设备绑定已写入 SQLite')
    await clickText('VPS 映射')
    await fill('input[placeholder="与连接中的最终节点名称一致"]', fixture[0].chains[0])
    await fill('input[placeholder="例如：HK2"]', '验收入口')
    await fill('input[placeholder="例如：HKG"]', '验收落地')
    await clickText('保存映射')
    check(
      (await waitFor(async () => (await request('nodes')).length === 1)) !== null,
      '通过页面保存入口与落地 VPS',
    )
    await sleep(500)
    await clickText('统计概览')
    await clickText('刷新')
    check(
      (await waitFor(() =>
        page.evaluate(`document.querySelector('table')?.innerText.includes('验收 Mac')`),
      )) !== null,
      '设备统计展示服务端机器名',
    )
    const select = async (index, value) =>
      page.evaluate(
        `(() => { const el=document.querySelectorAll('select')[${index}]; el.value=${JSON.stringify(value)}; el.dispatchEvent(new Event('change',{bubbles:true})); })()`,
      )
    await select(2, devices[0].id)
    await sleep(300)
    await select(1, 'exit_vps')
    check(
      (await waitFor(() =>
        page.evaluate(`document.querySelector('table')?.innerText.includes('验收落地')`),
      )) !== null,
      '设备与落地 VPS 交叉查询',
    )
    const upload = (await request(`summary?dimension=device&device=${devices[0].id}`)).total.upload
    check(upload > 0, '绑定后产生的流量已按设备归属')
    await page.screenshot(join(temp, 'desktop.png'))
    await page.call('Emulation.setDeviceMetricsOverride', {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    })
    await sleep(300)
    check(
      await page.evaluate(`document.documentElement.scrollWidth <= innerWidth`),
      '390px 窄屏无页面级横向溢出',
    )
    check(
      await page.evaluate(
        `!![...document.querySelectorAll('.tab-bar button')].find(b=>b.textContent.includes('流量统计'))`,
      ),
      '移动导航包含统计入口',
    )
    await page.screenshot(join(temp, 'mobile.png'))
    await page.goto(`${harness.app.url}/#/connections`)
    check(
      (await waitFor(() => page.evaluate(`document.body?.innerText.includes('验收 Mac')`))) !==
        null,
      '原连接列表复用服务端设备名称',
    )
    await page.evaluate(`localStorage.setItem('config/connection-display-style','table')`)
    await page.reload()
    check(
      (await waitFor(() =>
        page.evaluate(
          `document.querySelector('thead')?.innerText.includes('主机名') && document.querySelector('thead')?.innerText.includes('源IP')`,
        ),
      )) !== null,
      '连接表格独立显示主机名与源 IP 列',
    )
    check(
      (await waitFor(() =>
        page.evaluate(
          `document.querySelector('tbody')?.innerText.includes('192.168.1.2') && document.querySelector('tbody')?.innerText.includes('验收 Mac')`,
        ),
      )) !== null,
      '原始 IP 与设备名称同时保留',
    )
    await page.evaluate(`document.querySelector('[data-device-ip="192.168.1.2"]').click()`)
    check(
      (await waitFor(() =>
        page.evaluate(`document.querySelector('.modal-open')?.innerText.includes('设备绑定')`),
      )) !== null,
      '主机名单元格就地打开设备绑定',
    )
    await page.evaluate(
      `(() => { const input=document.querySelector('.modal-open input[placeholder="例如：工作电脑"]'); input.value='改名 Mac'; input.dispatchEvent(new Event('input',{bubbles:true})); })()`,
    )
    await page.evaluate(`document.querySelector('.modal-open form').requestSubmit()`)
    check(
      (await waitFor(() =>
        page.evaluate(`document.querySelector('tbody')?.innerText.includes('改名 Mac')`),
      )) !== null,
      '就地保存后连接表格立即更新主机名',
    )
    check((await request('devices'))[0].id === devices[0].id, '就地编辑保留原设备身份与历史关联')
    await page.call('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    })
    await page.screenshot(join(temp, 'connection-table.png'))
    await page.evaluate(`document.querySelector('tbody tr td').click()`)
    check(
      (await waitFor(() =>
        page.evaluate(
          `!![...document.querySelectorAll('.modal-open button')].find(b=>b.textContent.includes('编辑设备名称与 IP 绑定'))`,
        ),
      )) !== null,
      '原连接详情保留并提供设备绑定入口',
    )
    await page.evaluate(
      `[...document.querySelectorAll('.modal-open button')].find(b=>b.textContent.includes('编辑设备名称与 IP 绑定')).click()`,
    )
    check(
      (await waitFor(() =>
        page.evaluate(
          `(() => { const input=document.querySelector('.stats-integration-content input[placeholder="例如：工作电脑"]'); if(!input) return false; const r=input.getBoundingClientRect(); return !!document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.closest('.stats-integration-content') })()`,
        ),
      )) !== null,
      '设备编辑弹层位于原连接详情上方，可正常操作',
    )
    await page.evaluate(
      `document.querySelector('.modal-open:has(.stats-integration-content) button[aria-label="close"]').click()`,
    )
    await page.evaluate(
      `[...document.querySelectorAll('.modal-open button[aria-label="close"]')].forEach(b=>b.click())`,
    )
    // Configuration mismatch must fail closed rather than quietly displaying another source.
    await page.evaluate(
      `localStorage.setItem('stats/service-configs', ${JSON.stringify(JSON.stringify({ perf: { url: base, sourceId: 'wrong-source' } }))})`,
    )
    await page.goto(`${harness.app.url}/#/traffic-stats`)
    await waitFor(() =>
      page.evaluate(`location.hash.includes('traffic-stats') && !!document.querySelector('h1')`),
    )
    await page.reload()
    const mismatch = await waitFor(() =>
      page.evaluate(`document.body?.innerText.includes('采集源 ID 不一致')`),
    )
    if (mismatch === null)
      console.log(
        await page.evaluate(
          `JSON.stringify({hash:location.hash, text:document.body?.innerText, config:localStorage.getItem('stats/service-configs')})`,
        ),
      )
    check(mismatch !== null, '采集源身份不匹配时阻止展示')
    // Keep screenshots only when the caller explicitly requests output outside the repository.
    if (process.env.STATS_SCREENSHOT_DIR) {
      const { mkdir, copyFile } = await import('node:fs/promises')
      await mkdir(process.env.STATS_SCREENSHOT_DIR, { recursive: true })
      for (const name of [
        'desktop.png',
        'mobile.png',
        'proxy-cards.png',
        'proxy-cards-mobile.png',
        'connection-table.png',
      ])
        await copyFile(join(temp, name), join(process.env.STATS_SCREENSHOT_DIR, name))
    }
  } finally {
    await page.close()
  }
  const before = (await request('summary')).total.upload
  await sleep(500)
  check((await request('summary')).total.upload > before, '关闭页面后后台继续采集并存储')
  console.log(`${checks} 项浏览器检查通过`)
} finally {
  if (child && child.exitCode === null) {
    const exited = new Promise((resolve) => child.once('exit', resolve))
    child.kill('SIGTERM')
    await Promise.race([exited, sleep(3000)])
    if (child.exitCode === null) {
      child.kill('SIGKILL')
      await exited
    }
  }
  if (mock) {
    mock.closeAllConnections?.()
    await new Promise((resolve) => mock.close(resolve))
  }
  if (harness) await harness.close()
  await rm(temp, { recursive: true, force: true })
}
