import { useEffect, useState } from 'react'
import { Network, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { authApi } from '@/api/client'
import type { AuthConfigResponse } from '@/api/client'
import { useAuthStore } from '@/stores/authStore'

export function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [authCfg, setAuthCfg] = useState<AuthConfigResponse | null>(null)
  const login = useAuthStore((s) => s.login)

  useEffect(() => {
    let cancel = false
    authApi
      .fetchConfig()
      .then((r) => {
        if (!cancel) setAuthCfg(r.data)
      })
      .catch(() => {
        if (!cancel) {
          setAuthCfg({
            authentik_oidc_enabled: false,
            allow_local_login: false,
            setup_pending: false,
          })
        }
      })
    return () => {
      cancel = true
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await authApi.login(username, password)
      login(res.data.access_token)
    } catch (err: unknown) {
      const hasResponse = err && typeof err === 'object' && 'response' in err
      const status = hasResponse ? (err as { response?: { status?: number } }).response?.status : undefined
      if (status === 403) {
        setError('Local password login is disabled — use SSO.')
      } else {
        setError(hasResponse ? 'Invalid username or password' : 'Could not reach the server — check your CORS_ORIGINS setting')
      }
    } finally {
      setLoading(false)
    }
  }

  const showLocal = Boolean(authCfg?.allow_local_login)
  const showSso = Boolean(authCfg?.authentik_oidc_enabled && !authCfg?.setup_pending)

  if (!authCfg) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-[#0d1117] gap-2 text-muted-foreground">
        <Loader2 className="animate-spin text-[#00d4ff]" size={22} />
      </div>
    )
  }

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-[#0d1117]">
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: 'linear-gradient(#00d4ff 1px, transparent 1px), linear-gradient(90deg, #00d4ff 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      <div className="relative w-full max-w-sm px-4">
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/20">
            <Network size={28} className="text-[#00d4ff]" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold text-foreground tracking-wide">Homelable</h1>
            <p className="text-xs text-muted-foreground mt-0.5">HomeLab Visualizer</p>
          </div>
        </div>

        {!showLocal && !showSso && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 text-center text-sm text-muted-foreground">
            SSO is not configured. Complete first-time setup or contact your administrator.
          </div>
        )}

        {showSso && (
          <div className="flex flex-col gap-4 bg-[#161b22] border border-[#30363d] rounded-xl p-6">
            <a
              href="/api/v1/auth/oidc/login"
              className="inline-flex h-10 w-full items-center justify-center rounded-lg bg-[#00d4ff] text-[#0d1117] text-sm font-semibold hover:bg-[#00d4ff]/90"
            >
              Sign in with Authentik
            </a>
            {!showLocal && (
              <p className="text-[10px] text-muted-foreground text-center leading-snug">
                SSO is managed under <span className="font-mono">Settings</span> → Authentik after you sign in.
              </p>
            )}
          </div>
        )}

        {showLocal && (
          <form
            onSubmit={handleSubmit}
            className={`flex flex-col gap-4 bg-[#161b22] border border-[#30363d] rounded-xl p-6 ${showSso ? 'mt-4' : ''}`}
          >
            {showSso && (
              <p className="text-[10px] text-muted-foreground text-center uppercase tracking-wider">
                Or use local account
              </p>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="username" className="text-xs text-muted-foreground">Username</Label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="bg-[#21262d] border-[#30363d] focus-visible:ring-[#00d4ff]/50 text-sm"
                placeholder="admin"
                required
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="password" className="text-xs text-muted-foreground">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-[#21262d] border-[#30363d] focus-visible:ring-[#00d4ff]/50 text-sm"
                required
              />
            </div>

            {error && (
              <p className="text-xs text-[#f85149] text-center">{error}</p>
            )}

            <Button
              type="submit"
              disabled={loading}
              className="mt-1 bg-[#00d4ff] text-[#0d1117] hover:bg-[#00d4ff]/90 font-medium"
            >
              {loading ? <Loader2 size={15} className="animate-spin" /> : 'Sign in'}
            </Button>

            {showSso && (
              <a
                href="/api/v1/auth/oidc/login"
                className="inline-flex h-8 w-full items-center justify-center rounded-lg border border-[#30363d] bg-transparent text-xs font-medium hover:bg-[#21262d]"
              >
                Sign in with Authentik instead
              </a>
            )}
          </form>
        )}

        <p className="text-center text-[10px] text-muted-foreground/40 mt-4 leading-relaxed">
          {showLocal ? (
            <>Local login can be disabled from Settings → Authentik.</>
          ) : (
            <>Authenticated via Authentik. Change provider values in Settings → Authentik.</>
          )}
        </p>
      </div>
    </div>
  )
}
