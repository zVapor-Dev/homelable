import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { LoginPage } from '../LoginPage'
import { useAuthStore } from '@/stores/authStore'

vi.mock('@/api/client', () => ({
  authApi: {
    login: vi.fn(),
    fetchConfig: vi.fn().mockResolvedValue({
      data: {
        authentik_oidc_enabled: false,
        allow_local_login: true,
        setup_pending: false,
      },
    }),
  },
}))

import { authApi } from '@/api/client'

describe('LoginPage', () => {
  beforeEach(() => {
    useAuthStore.setState({ token: null, isAuthenticated: false })
    vi.mocked(authApi.login).mockReset()
    vi.mocked(authApi.fetchConfig).mockReset()
    vi.mocked(authApi.fetchConfig).mockResolvedValue({
      data: {
        authentik_oidc_enabled: false,
        allow_local_login: true,
        setup_pending: false,
      },
    } as never)
  })

  it('renders username and password fields when local login is allowed', async () => {
    render(<LoginPage />)
    expect(await screen.findByLabelText('Username')).toBeDefined()
    expect(await screen.findByLabelText('Password')).toBeDefined()
  })

  it('renders a Sign in button', async () => {
    render(<LoginPage />)
    expect(await screen.findByRole('button', { name: /sign in/i })).toBeDefined()
  })

  it('password field type is password', async () => {
    render(<LoginPage />)
    const pw = (await screen.findByLabelText('Password')) as HTMLInputElement
    expect(pw.type).toBe('password')
  })

  it('username field autocomplete=username', async () => {
    render(<LoginPage />)
    const un = (await screen.findByLabelText('Username')) as HTMLInputElement
    expect(un.getAttribute('autocomplete')).toBe('username')
  })

  it('shows generic error on 401 — no enumeration', async () => {
    vi.mocked(authApi.login).mockRejectedValue({ response: { status: 401 } })
    render(<LoginPage />)
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(await screen.findByLabelText('Password'), { target: { value: 'wrongpass' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)
    await waitFor(() => {
      expect(screen.getByText('Invalid username or password')).toBeDefined()
    })
    const errors = document.querySelectorAll('p.text-\\[\\#f85149\\]')
    expect(errors.length).toBe(1)
  })

  it('shows SSO link when OIDC enabled and setup done', async () => {
    vi.mocked(authApi.fetchConfig).mockResolvedValue({
      data: {
        authentik_oidc_enabled: true,
        allow_local_login: false,
        setup_pending: false,
      },
    } as never)
    render(<LoginPage />)
    const link = await screen.findByRole('link', { name: /sign in with authentik/i })
    expect(link.getAttribute('href')).toBe('/api/v1/auth/oidc/login')
    expect(screen.queryByLabelText('Username')).toBeNull()
  })

  it('shows Authentik link when OIDC enabled and local login allowed', async () => {
    vi.mocked(authApi.fetchConfig).mockResolvedValue({
      data: {
        authentik_oidc_enabled: true,
        allow_local_login: true,
        setup_pending: false,
      },
    } as never)
    render(<LoginPage />)
    await waitFor(() => {
      expect(screen.getByRole('link', { name: /sign in with authentik instead/i })).toBeDefined()
    })
  })

  it('shows 403 copy when local login disabled server-side', async () => {
    vi.mocked(authApi.fetchConfig).mockResolvedValue({
      data: { authentik_oidc_enabled: false, allow_local_login: true, setup_pending: false },
    } as never)
    vi.mocked(authApi.login).mockRejectedValue({ response: { status: 403 } })
    render(<LoginPage />)
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(await screen.findByLabelText('Password'), { target: { value: 'x' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)
    await waitFor(() => {
      expect(screen.getByText(/Local password login is disabled/)).toBeDefined()
    })
  })
})
