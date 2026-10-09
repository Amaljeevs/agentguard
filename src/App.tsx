import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  RotateCcw,
  FileCode2,
  Terminal,
  Lock,
  Layers,
  FileText,
  Copy,
  Check,
  Cpu,
  Server,
  ArrowRight,
  GitBranch,
  Key,
  ExternalLink,
  ChevronRight,
  BookOpen,
  Sparkles
} from 'lucide-react';

import {
  AgentType,
  AuthorizationRequest,
  AuthorizationDecision,
  DEFAULT_POLICY,
  evaluatePolicy
} from './simulator/policyEngine';

import { CODE_FILES, CodeFile } from './data/codeFiles';

interface Preset {
  name: string;
  badge: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
  description: string;
  request: AuthorizationRequest;
}

const PRESETS: Preset[] = [
  {
    name: 'Developer Agent in Dev DB',
    badge: 'ALLOW',
    description: 'Standard software engineer assistant querying dev database.',
    request: {
      subject: {
        agentId: 'coding-agent-17',
        agentType: 'AUTONOMOUS',
        roles: ['developer'],
        permissions: ['git.read'],
        delegatedBy: 'user-amaljeev',
        sessionId: 'sess-8912',
        issuedAt: new Date(Date.now() - 600000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
      action: {
        name: 'database.query',
        parameters: { sql: 'SELECT id, name FROM dev_customers LIMIT 10;' }
      },
      resource: {
        type: 'database',
        id: 'customer-dev-db',
        tags: { env: 'dev' }
      },
      context: {
        environment: 'development',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'Developer in Production DB',
    badge: 'DENY',
    description: 'Rule "deny-dev-prod-db" explicitly blocks developers in production.',
    request: {
      subject: {
        agentId: 'coding-agent-17',
        agentType: 'AUTONOMOUS',
        roles: ['developer'],
        permissions: [],
        delegatedBy: 'user-amaljeev',
        sessionId: 'sess-8912',
        issuedAt: new Date(Date.now() - 600000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
      action: {
        name: 'database.query',
        parameters: { sql: 'SELECT * FROM prod_credentials;' }
      },
      resource: {
        type: 'database',
        id: 'customer-prod-db',
        tags: { env: 'production' }
      },
      context: {
        environment: 'production',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'DevOps Production K8s Deploy',
    badge: 'APPROVAL_REQUIRED',
    description: 'Production deployment triggers human sign-off policy.',
    request: {
      subject: {
        agentId: 'devops-bot-04',
        agentType: 'AUTONOMOUS',
        roles: ['devops'],
        permissions: [],
        delegatedBy: 'release-lead',
        sessionId: 'sess-k8s-deploy',
        issuedAt: new Date(Date.now() - 300000).toISOString(),
        expiresAt: new Date(Date.now() + 7200000).toISOString(),
      },
      action: {
        name: 'kubernetes.deploy',
        parameters: { service: 'payment-gateway', image: 'v2.4.1' }
      },
      resource: {
        type: 'k8s_cluster',
        id: 'prod-us-east-1',
        tags: { tier: 'tier-1' }
      },
      context: {
        environment: 'production',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'DevOps Staging K8s Deploy',
    badge: 'ALLOW',
    description: 'Allowed directly because human approval only targets production.',
    request: {
      subject: {
        agentId: 'devops-bot-04',
        agentType: 'AUTONOMOUS',
        roles: ['devops'],
        permissions: [],
        delegatedBy: 'release-lead',
        sessionId: 'sess-staging',
        issuedAt: new Date(Date.now() - 300000).toISOString(),
        expiresAt: new Date(Date.now() + 7200000).toISOString(),
      },
      action: {
        name: 'kubernetes.deploy',
        parameters: { service: 'payment-gateway', image: 'v2.4.1-rc1' }
      },
      resource: {
        type: 'k8s_cluster',
        id: 'staging-cluster',
        tags: { tier: 'staging' }
      },
      context: {
        environment: 'staging',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'Destructive DROP Table in Prod',
    badge: 'DENY',
    description: 'Global safety rule explicitly rejects destructive actions in prod.',
    request: {
      subject: {
        agentId: 'dba-agent-99',
        agentType: 'AUTONOMOUS',
        roles: ['devops'],
        permissions: [],
        delegatedBy: 'lead-architect',
        sessionId: 'sess-dba',
        issuedAt: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
      action: {
        name: 'database.drop',
        parameters: { table: 'audit_logs' }
      },
      resource: {
        type: 'database',
        id: 'primary-db',
        tags: { env: 'production' }
      },
      context: {
        environment: 'production',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'Expired Identity Token Attack',
    badge: 'DENY',
    description: 'Expired credentials fail closed before policy graph evaluation.',
    request: {
      subject: {
        agentId: 'stale-agent-01',
        agentType: 'WORKER',
        roles: ['admin'],
        permissions: ['*'],
        delegatedBy: 'compromised-account',
        sessionId: 'sess-expired',
        issuedAt: new Date(Date.now() - 7200000).toISOString(),
        expiresAt: new Date(Date.now() - 1800000).toISOString(),
      },
      action: {
        name: 'database.query',
        parameters: { sql: 'SELECT * FROM users;' }
      },
      resource: {
        type: 'database',
        id: 'customer-db',
        tags: {}
      },
      context: {
        environment: 'development',
        timestamp: new Date().toISOString()
      }
    }
  },
  {
    name: 'Unmapped Action (Least Privilege)',
    badge: 'DENY',
    description: 'Deny by default kicks in when no permission or rule grants the action.',
    request: {
      subject: {
        agentId: 'coding-agent-17',
        agentType: 'AUTONOMOUS',
        roles: ['developer'],
        permissions: [],
        delegatedBy: 'user-amaljeev',
        sessionId: 'sess-8912',
        issuedAt: new Date(Date.now() - 600000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
      action: {
        name: 'cloud.provision_vm',
        parameters: { instanceType: 'c6g.4xlarge' }
      },
      resource: {
        type: 'cloud_infra',
        id: 'aws-us-west-2',
        tags: {}
      },
      context: {
        environment: 'development',
        timestamp: new Date().toISOString()
      }
    }
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'simulator' | 'code' | 'policy' | 'architecture' | 'docs'>('simulator');
  const [selectedPresetIndex, setSelectedPresetIndex] = useState(0);
  const [currentRequest, setCurrentRequest] = useState<AuthorizationRequest>(PRESETS[0].request);
  const [decision, setDecision] = useState<AuthorizationDecision>(() => evaluatePolicy(DEFAULT_POLICY, PRESETS[0].request));
  const [selectedCodeFile, setSelectedCodeFile] = useState<CodeFile>(CODE_FILES[0]);
  const [copiedCode, setCopiedCode] = useState(false);

  const handlePresetSelect = (index: number) => {
    setSelectedPresetIndex(index);
    const chosen = PRESETS[index];
    setCurrentRequest(chosen.request);
    setDecision(evaluatePolicy(DEFAULT_POLICY, chosen.request));
  };

  const handleRunEvaluation = () => {
    setDecision(evaluatePolicy(DEFAULT_POLICY, currentRequest));
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500/30 selection:text-indigo-200">
      {/* Top Banner / Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-indigo-600 to-violet-700 flex items-center justify-center shadow-lg shadow-indigo-500/20 ring-1 ring-indigo-400/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight text-white">AgentGuard</span>
                <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                  v0.1.0 (Full Release)
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  Milestones 1–5 Complete
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Open-Source Authorization & Governance for AI Agents & MCP (Java 21 / Spring Boot)
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex space-x-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('simulator')}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all ${
                activeTab === 'simulator'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Policy Simulator</span>
            </button>
            <button
              onClick={() => setActiveTab('code')}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all ${
                activeTab === 'code'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileCode2 className="w-4 h-4" />
              <span>Java Core Code</span>
            </button>
            <button
              onClick={() => setActiveTab('policy')}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all ${
                activeTab === 'policy'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>YAML Policy & Schema</span>
            </button>
            <button
              onClick={() => setActiveTab('architecture')}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all ${
                activeTab === 'architecture'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Architecture</span>
            </button>
            <button
              onClick={() => setActiveTab('docs')}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-all ${
                activeTab === 'docs'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Docs & Guides</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab === 'simulator' && (
          <div className="space-y-6">
            {/* Presets Horizontal Bar */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                  Quick Test Scenarios (Security Matrix)
                </span>
                <span className="text-xs text-slate-400">
                  Select a test case to prefill Subject, Action, Resource & Context
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                {PRESETS.map((preset, idx) => (
                  <button
                    key={preset.name}
                    onClick={() => handlePresetSelect(idx)}
                    className={`text-left p-2.5 rounded-xl border text-xs transition-all relative overflow-hidden ${
                      selectedPresetIndex === idx
                        ? 'bg-indigo-950/40 border-indigo-500/50 shadow-sm shadow-indigo-500/10 ring-1 ring-indigo-500/30'
                        : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-800/60 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-slate-200 truncate">{preset.name}</span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
                          preset.badge === 'ALLOW'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : preset.badge === 'DENY'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {preset.badge}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2">{preset.description}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Split Screen: Request Form (Left) & Decision Evaluation / Trace (Right) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Authorization Request Inspector & Controls */}
              <div className="lg:col-span-6 space-y-4">
                <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-7 h-7 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-mono text-xs font-bold border border-indigo-500/30">
                        IN
                      </div>
                      <h2 className="font-semibold text-sm text-slate-200">
                        AuthorizationRequest (Java Domain Object)
                      </h2>
                    </div>
                    <button
                      onClick={handleRunEvaluation}
                      className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Run PDP Evaluation</span>
                    </button>
                  </div>

                  {/* Subject Details */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-semibold text-indigo-300 flex items-center gap-1.5">
                        <Key className="w-3.5 h-3.5" />
                        1. Subject (AgentIdentity)
                      </label>
                      <span className="text-[11px] font-mono text-slate-400">
                        Delegated By: {currentRequest.subject.delegatedBy || 'None'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-400 block mb-1">agentId:</span>
                        <input
                          type="text"
                          value={currentRequest.subject.agentId}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              subject: { ...currentRequest.subject, agentId: e.target.value }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-indigo-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div>
                        <span className="text-slate-400 block mb-1">agentType:</span>
                        <select
                          value={currentRequest.subject.agentType}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              subject: {
                                ...currentRequest.subject,
                                agentType: e.target.value as AgentType
                              }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        >
                          <option value="AUTONOMOUS">AUTONOMOUS</option>
                          <option value="ASSISTANT">ASSISTANT</option>
                          <option value="WORKER">WORKER</option>
                          <option value="SYSTEM">SYSTEM</option>
                        </select>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-400 block mb-1">Roles (comma-separated):</span>
                        <input
                          type="text"
                          value={currentRequest.subject.roles.join(', ')}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              subject: {
                                ...currentRequest.subject,
                                roles: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                              }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-amber-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div>
                        <span className="text-slate-400 block mb-1">Explicit Permissions:</span>
                        <input
                          type="text"
                          value={currentRequest.subject.permissions.join(', ')}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              subject: {
                                ...currentRequest.subject,
                                permissions: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                              }
                            })
                          }
                          placeholder="e.g. git.read, logs.read"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-emerald-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Action Details */}
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <label className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5" />
                      2. Action (Target MCP Tool / Operation)
                    </label>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-400 block mb-1">action.name:</span>
                        <input
                          type="text"
                          value={currentRequest.action.name}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              action: { ...currentRequest.action, name: e.target.value }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-emerald-300 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div>
                        <span className="text-slate-400 block mb-1">parameters preview:</span>
                        <input
                          type="text"
                          readOnly
                          value={JSON.stringify(currentRequest.action.parameters)}
                          className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-[11px] text-slate-400"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Resource & Context */}
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <label className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5" />
                      3. Resource & AuthorizationContext
                    </label>
                    <div className="grid grid-cols-3 gap-3 text-xs">
                      <div>
                        <span className="text-slate-400 block mb-1">resource.type:</span>
                        <input
                          type="text"
                          value={currentRequest.resource.type}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              resource: { ...currentRequest.resource, type: e.target.value }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div>
                        <span className="text-slate-400 block mb-1">resource.id:</span>
                        <input
                          type="text"
                          value={currentRequest.resource.id}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              resource: { ...currentRequest.resource, id: e.target.value }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div>
                        <span className="text-slate-400 block mb-1">context.environment:</span>
                        <select
                          value={currentRequest.context.environment}
                          onChange={e =>
                            setCurrentRequest({
                              ...currentRequest,
                              context: { ...currentRequest.context, environment: e.target.value }
                            })
                          }
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 font-mono text-xs text-violet-300 focus:outline-none focus:border-indigo-500"
                        >
                          <option value="development">development</option>
                          <option value="staging">staging</option>
                          <option value="production">production</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column: PDP Decision Card, Execution Trace, and Audit Log */}
              <div className="lg:col-span-6 space-y-4">
                {/* Decision Banner */}
                <div
                  className={`rounded-2xl border p-5 transition-all shadow-xl ${
                    decision.decision === 'ALLOW'
                      ? 'bg-emerald-950/20 border-emerald-500/50 shadow-emerald-500/5'
                      : decision.decision === 'DENY'
                      ? 'bg-rose-950/20 border-rose-500/50 shadow-rose-500/5'
                      : 'bg-amber-950/20 border-amber-500/50 shadow-amber-500/5'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <div
                        className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold shadow-md ${
                          decision.decision === 'ALLOW'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                            : decision.decision === 'DENY'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        }`}
                      >
                        {decision.decision === 'ALLOW' ? (
                          <ShieldCheck className="w-7 h-7" />
                        ) : decision.decision === 'DENY' ? (
                          <ShieldAlert className="w-7 h-7" />
                        ) : (
                          <AlertTriangle className="w-7 h-7" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span
                            className={`text-xl font-extrabold font-mono tracking-tight ${
                              decision.decision === 'ALLOW'
                                ? 'text-emerald-400'
                                : decision.decision === 'DENY'
                                ? 'text-rose-400'
                                : 'text-amber-400'
                            }`}
                          >
                            {decision.decision}
                          </span>
                          {decision.matchedRuleId && (
                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                              rule: {decision.matchedRuleId}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-300 mt-1 font-medium">{decision.reason}</p>
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Evaluated: {new Date(decision.evaluatedAt).toLocaleTimeString()}</span>
                    <span>PolicySet: {decision.matchedPolicyName || DEFAULT_POLICY.name}</span>
                  </div>
                </div>

                {/* Step-by-Step PDP Evaluation Trace */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-indigo-400" />
                      PDP Decision Trace (Deterministic Execution)
                    </h3>
                    <span className="text-[11px] font-mono text-slate-500">
                      {decision.trace.length} stages evaluated
                    </span>
                  </div>

                  <div className="space-y-2">
                    {decision.trace.map((step, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-xl border text-xs flex items-start space-x-2.5 transition-all ${
                          step.status === 'triggered'
                            ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                            : step.status === 'passed'
                            ? 'bg-slate-900/80 border-slate-800/80 text-slate-300'
                            : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
                        }`}
                      >
                        <div className="mt-0.5">
                          {step.status === 'passed' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          ) : step.status === 'triggered' ? (
                            <AlertTriangle className="w-4 h-4 text-amber-400" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-400" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-200 text-[11px]">
                              {step.step}
                            </span>
                            <span
                              className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-bold ${
                                step.status === 'passed'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : step.status === 'triggered'
                                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                  : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                              }`}
                            >
                              {step.status}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 mt-0.5">{step.details}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Audit Event Payload Preview */}
                <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 shadow-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-indigo-400" />
                      Generated Audit Event (AuditEventRecord)
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      Sanitized & Parameter Masked
                    </span>
                  </div>
                  <pre className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                    {JSON.stringify(
                      {
                        eventId: 'evt-' + Math.random().toString(36).substring(2, 9),
                        timestamp: decision.evaluatedAt,
                        agentId: currentRequest.subject.agentId,
                        role: currentRequest.subject.roles[0] || 'NONE',
                        action: currentRequest.action.name,
                        resource: `${currentRequest.resource.type}:${currentRequest.resource.id}`,
                        environment: currentRequest.context.environment,
                        decision: decision.decision,
                        reason: decision.reason,
                        policy: decision.matchedPolicyName || 'enterprise-mcp-governance',
                        delegatedBy: currentRequest.subject.delegatedBy || null,
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Java Source Code Explorer Tab */}
        {activeTab === 'code' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/60 p-4 rounded-2xl border border-slate-800">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <FileCode2 className="w-5 h-5 text-indigo-400" />
                  AgentGuard Java 21 Source Explorer (Milestone 1)
                </h2>
                <p className="text-xs text-slate-400">
                  Inspect the pure Java 21 core records, engine contracts, and JUnit 5 security tests.
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-xs px-2.5 py-1 rounded-lg font-mono bg-slate-800 text-slate-300 border border-slate-700">
                  Zero External Dependencies
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* File List Navigation */}
              <div className="lg:col-span-4 bg-slate-900/60 border border-slate-800 rounded-2xl p-3 space-y-1.5 shadow-lg">
                <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800">
                  agentguard-core / specification
                </div>
                {CODE_FILES.map(file => (
                  <button
                    key={file.path}
                    onClick={() => setSelectedCodeFile(file)}
                    className={`w-full text-left px-3 py-2.5 rounded-xl text-xs transition-all flex items-center justify-between ${
                      selectedCodeFile.path === file.path
                        ? 'bg-indigo-600 text-white font-semibold shadow-md shadow-indigo-600/20'
                        : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <FileCode2 className="w-4 h-4 flex-shrink-0" />
                      <span className="truncate">{file.name}</span>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        selectedCodeFile.path === file.path
                          ? 'bg-indigo-700/60 text-indigo-100'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {file.module}
                    </span>
                  </button>
                ))}
              </div>

              {/* Code Display */}
              <div className="lg:col-span-8 bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-lg flex flex-col">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-sm font-bold text-indigo-300">
                        {selectedCodeFile.name}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                        {selectedCodeFile.path}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{selectedCodeFile.description}</p>
                  </div>
                  <button
                    onClick={() => handleCopyCode(selectedCodeFile.content)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-all border border-slate-700"
                  >
                    {copiedCode ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="relative flex-1 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                  <pre className="p-4 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed">
                    {selectedCodeFile.content}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* YAML Policy & Schema Tab */}
        {activeTab === 'policy' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 p-4 rounded-2xl border border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-indigo-400" />
                  Portable Policy Definition & JSON Schema
                </h2>
                <p className="text-xs text-slate-400">
                  Language-neutral declarative YAML specification validated at application bootstrap.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* YAML Policy Document */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-lg">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                    src/main/resources/agentguard-policy.yaml
                  </span>
                  <span className="text-[10px] font-mono bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/20">
                    version: 1.0
                  </span>
                </div>
                <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto leading-relaxed">
{`version: "1.0"
metadata:
  name: "enterprise-mcp-governance"
  description: "Core access policy for developer, devops, and automated agents"

roles:
  developer:
    description: "Standard software development assistant"
    permissions:
      - "git.read"
      - "git.write"
      - "logs.read"
      - "database.query"

  devops:
    description: "Infrastructure management agent"
    permissions:
      - "logs.read"
      - "kubernetes.*"
      - "database.*"

  security-auditor:
    description: "Read-only compliance inspection agent"
    permissions:
      - "*.read"

  admin:
    description: "Universal administrator agent"
    permissions:
      - "*"

rules:
  # 1. Deny developers querying production databases
  - id: "deny-dev-prod-db"
    effect: DENY
    target:
      roles: ["developer"]
      actions: ["database.query", "database.write"]
      resources:
        type: "database"
      conditions:
        environment:
          equals: "production"

  # 2. Production deployments require human approval
  - id: "prod-deploy-approval"
    effect: APPROVAL_REQUIRED
    target:
      actions: ["kubernetes.deploy"]
      conditions:
        environment:
          equals: "production"

  # 3. Deny destructive actions in production across all agents
  - id: "deny-destructive-drop-prod"
    effect: DENY
    target:
      actions: ["database.drop", "database.truncate"]
      conditions:
        environment:
          equals: "production"`}
                </pre>
              </div>

              {/* Roles & Rules Breakdown */}
              <div className="space-y-4">
                <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-lg">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Active RBAC Roles
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {Object.entries(DEFAULT_POLICY.roles).map(([roleName, def]) => (
                      <div
                        key={roleName}
                        className="bg-slate-950/70 border border-slate-800 rounded-xl p-3 text-xs"
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="font-bold text-indigo-300 font-mono">{roleName}</span>
                          <span className="text-[10px] font-mono text-slate-400">
                            {def.permissions.length} perms
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mb-2">{def.description}</p>
                        <div className="flex flex-wrap gap-1">
                          {def.permissions.map(p => (
                            <span
                              key={p}
                              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-emerald-400 border border-slate-800"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-lg">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Active Contextual Rules (Deny Precedence & Approval)
                  </h3>
                  <div className="space-y-2">
                    {DEFAULT_POLICY.rules.map(rule => (
                      <div
                        key={rule.id}
                        className="bg-slate-950/70 border border-slate-800 rounded-xl p-3 text-xs flex items-start justify-between"
                      >
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <span className="font-mono font-bold text-slate-200">{rule.id}</span>
                            <span
                              className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold ${
                                rule.effect === 'DENY'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              }`}
                            >
                              {rule.effect}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400">{rule.description}</p>
                        </div>
                        <div className="text-[10px] font-mono text-slate-400 text-right">
                          Env: {rule.environments?.join(', ') || 'ANY'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Architecture & Threat Model Tab */}
        {activeTab === 'architecture' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 p-4 rounded-2xl border border-slate-800">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-400" />
                Target Architecture & Zero-Trust Threat Model
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                How AgentGuard isolates agent authority, enforces invariants, and prevents prompt injection privilege escalation.
              </p>
            </div>

            {/* Architecture Diagram Card */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                End-to-End MCP Tool Enforcement Pipeline
              </h3>
              <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto leading-relaxed">
{`                    AI Agents (Interactive, Autonomous, or Workers)
                               │
                               ▼
               [Transport & OAuth 2.1 / JWT Bearer Authentication]
                 • Handshake, TLS, Token Verification (Spring Security)
                               │
                               ▼
               [AgentGuard Identity Resolution (PEP Hook)]
                 • Extract AgentIdentity (AgentId, Roles, Validity, Lineage)
                 • Verify Temporal Validity (Fail Closed if Expired)
                               │
                               ▼
               [AgentGuard Core Policy Engine (Stateless PDP)]
                 ├── 1. Evaluate Explicit DENY Rules (Deny Precedence)
                 ├── 2. Evaluate APPROVAL_REQUIRED Rules (Human Gatekeeper)
                 ├── 3. Evaluate Explicit ALLOW Rules
                 ├── 4. Evaluate RBAC Permissions (Hierarchical Wildcard Match)
                 └── 5. Default Fallback ──► DENY (Deny by Default)
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
            [ ALLOW ]     [ DENY ]    [ APPROVAL_REQUIRED ]
                │              │              │
                │          Audit Log      Audit Log
                │              │              │
                │         Throw Error   Halt Execution
                │         (Code -32003) (Code -32004)
                ▼
        [ Execute MCP Tool ] (Spring AI @Tool / io.modelcontextprotocol)
                │
     ┌──────────┼──────────┐
     ▼          ▼          ▼
   Git API   Database   K8s Cluster`}
              </div>
            </div>

            {/* Threat Matrix Table */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Security Threat Model & Mitigations
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                      <th className="py-2.5 px-3">ID</th>
                      <th className="py-2.5 px-3">Threat Vector</th>
                      <th className="py-2.5 px-3">Vulnerability Mechanism</th>
                      <th className="py-2.5 px-3">AgentGuard Architectural Defense</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-01</td>
                      <td className="py-3 px-3 font-semibold text-white">Confused Deputy / Prompt Hijack</td>
                      <td className="py-3 px-3 text-slate-400">Untrusted prompt induces agent to call destructive tool.</td>
                      <td className="py-3 px-3 text-emerald-300">Non-bypassable PDP. LLM prompts never make security decisions.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-02</td>
                      <td className="py-3 px-3 font-semibold text-white">Delegation Escalation</td>
                      <td className="py-3 px-3 text-slate-400">Agent A spawns Agent B to bypass role limits.</td>
                      <td className="py-3 px-3 text-emerald-300">Invariant: Delegated permissions must be a subset of delegator permissions.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-03</td>
                      <td className="py-3 px-3 font-semibold text-white">Identity Header Forgery</td>
                      <td className="py-3 px-3 text-slate-400">Attacker injects raw untrusted headers (e.g. X-Agent-Id).</td>
                      <td className="py-3 px-3 text-emerald-300">Identity resolved strictly from verified cryptographic JWT/SPIFFE tokens.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-04</td>
                      <td className="py-3 px-3 font-semibold text-white">Environment Bleed</td>
                      <td className="py-3 px-3 text-slate-400">Dev-authorized agent touches production database.</td>
                      <td className="py-3 px-3 text-emerald-300">Context-aware policy engine enforces strict environment tags.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-05</td>
                      <td className="py-3 px-3 font-semibold text-white">Fail-Open Misconfiguration</td>
                      <td className="py-3 px-3 text-slate-400">Syntax error in YAML policy allows unauthenticated actions.</td>
                      <td className="py-3 px-3 text-emerald-300">Startup schema validation fails closed; unmapped calls default to DENY.</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-3 font-mono text-indigo-400 font-bold">TM-06</td>
                      <td className="py-3 px-3 font-semibold text-white">Audit Log Secret Leakage</td>
                      <td className="py-3 px-3 text-slate-400">Database passwords or API tokens leak into audit events.</td>
                      <td className="py-3 px-3 text-emerald-300">Automatic parameter sanitization masks passwords, keys, and tokens.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Milestones Roadmap Card */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Milestone Roadmap Status
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200">
                  <div className="font-bold flex items-center justify-between mb-1">
                    <span>M1: Core Domain</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <p className="text-[11px] text-emerald-300/80">Complete (Pure Java 21, zero deps, JUnit 5 suite)</p>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200">
                  <div className="font-bold flex items-center justify-between mb-1">
                    <span>M2: Policy Loader</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <p className="text-[11px] text-emerald-300/80">Complete (Jackson YAML, DTOs, fail-closed validation, schema)</p>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200">
                  <div className="font-bold flex items-center justify-between mb-1">
                    <span>M3: Audit Engine</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <p className="text-[11px] text-emerald-300/80">Complete (SLF4J, AuditEvent, parameter sanitization, publishers)</p>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200">
                  <div className="font-bold flex items-center justify-between mb-1">
                    <span>M4: Spring &amp; MCP</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <p className="text-[11px] text-emerald-300/80">Complete (@AgentAuthorize, Spring AOP, MCP error codes, AutoConfig)</p>
                </div>
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200">
                  <div className="font-bold flex items-center justify-between mb-1">
                    <span>M5: Example MCP Server</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <p className="text-[11px] text-emerald-300/80">Complete (Working Spring Boot MCP app, integration tests)</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Documentation & Integration Guide Tab */}
        {activeTab === 'docs' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 p-5 rounded-2xl border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <BookOpen className="w-5 h-5 text-indigo-400" />
                  AgentGuard Integration &amp; Developer Guide
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Step-by-step instructions for securing Spring Boot MCP servers and AI agent tool invocations.
                </p>
              </div>
              <span className="text-xs font-mono px-3 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Production-Ready Specification
              </span>
            </div>

            {/* 4-Step Quick Start */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
              <h3 className="text-sm font-bold text-indigo-300 flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-mono">1</span>
                Add Maven Starter Dependency
              </h3>
              <p className="text-xs text-slate-400">
                Include the AgentGuard Spring Boot Starter in your project's <code className="text-indigo-300 font-mono">pom.xml</code>:
              </p>
              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto">
{`<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.2.0</version>
</dependency>`}
              </pre>

              <h3 className="text-sm font-bold text-indigo-300 flex items-center gap-2 pt-3 border-t border-slate-800">
                <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-mono">2</span>
                Configure Application Properties
              </h3>
              <p className="text-xs text-slate-400">
                Set policy file location and fallback execution environment in <code className="text-indigo-300 font-mono">application.yaml</code>:
              </p>
              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto">
{`agentguard:
  enabled: true
  policy-location: "classpath:agentguard-policy.yaml"
  environment: "development"
  audit:
    enabled: true
    mask-token: "[REDACTED]"
    sensitive-keys: ["password", "token", "secret", "apiKey"]`}
              </pre>

              <h3 className="text-sm font-bold text-indigo-300 flex items-center gap-2 pt-3 border-t border-slate-800">
                <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-mono">3</span>
                Define Policy (`agentguard-policy.yaml`)
              </h3>
              <p className="text-xs text-slate-400">
                Define RBAC roles, granted actions, and contextual deny/approval rules:
              </p>
              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto">
{`version: "1.0"
metadata:
  name: "enterprise-mcp-governance"

roles:
  developer:
    permissions: ["git.*", "logs.read", "database.query"]
  devops:
    permissions: ["logs.read", "kubernetes.*", "database.*"]

rules:
  # Deny developers querying production databases
  - id: "deny-dev-prod-db"
    effect: DENY
    target:
      roles: ["developer"]
      actions: ["database.query"]
      conditions:
        environment:
          equals: "production"

  # Production deployments require human approval
  - id: "prod-deploy-approval"
    effect: APPROVAL_REQUIRED
    target:
      actions: ["kubernetes.deploy"]
      conditions:
        environment:
          equals: "production"`}
              </pre>

              <h3 className="text-sm font-bold text-indigo-300 flex items-center gap-2 pt-3 border-t border-slate-800">
                <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-mono">4</span>
                Protect MCP Tools with `@AgentAuthorize`
              </h3>
              <p className="text-xs text-slate-400">
                Add annotations with explicit action tags and dynamic SpEL expressions:
              </p>
              <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-indigo-200 overflow-x-auto">
{`@Service
public class CloudTools {

    @McpTool(name = "queryDatabase")
    @AgentAuthorize(
        action = "database.query",
        resourceType = "database",
        resourceId = "#dbName",
        environment = "#env"
    )
    public List<Map<String, Object>> queryDatabase(String dbName, String sql, String env) {
        return dbClient.query(dbName, sql);
    }
}`}
              </pre>
            </div>

            {/* Error Mapping Table & Annotation Reference */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* MCP Error Codes */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  Model Context Protocol (MCP) Error Codes
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                        <th className="py-2 px-2.5">Code</th>
                        <th className="py-2 px-2.5">Constant</th>
                        <th className="py-2 px-2.5">Trigger Condition</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      <tr>
                        <td className="py-2.5 px-2.5 font-mono text-rose-400 font-bold">-32001</td>
                        <td className="py-2.5 px-2.5 font-mono text-slate-200">AUTHENTICATION_FAILED</td>
                        <td className="py-2.5 px-2.5 text-slate-400">Missing or expired agent token.</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-2.5 font-mono text-rose-400 font-bold">-32003</td>
                        <td className="py-2.5 px-2.5 font-mono text-slate-200">ACCESS_DENIED</td>
                        <td className="py-2.5 px-2.5 text-slate-400">Policy evaluates to DENY (explicit or default).</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-2.5 font-mono text-amber-400 font-bold">-32004</td>
                        <td className="py-2.5 px-2.5 font-mono text-slate-200">APPROVAL_REQUIRED</td>
                        <td className="py-2.5 px-2.5 text-slate-400">Operation requires human sign-off.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Annotation Parameters Reference */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <FileCode2 className="w-4 h-4 text-indigo-400" />
                  `@AgentAuthorize` Parameters
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                        <th className="py-2 px-2.5">Attribute</th>
                        <th className="py-2 px-2.5">Type</th>
                        <th className="py-2 px-2.5">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      <tr>
                        <td className="py-2 px-2.5 font-mono text-indigo-300">action</td>
                        <td className="py-2 px-2.5 font-mono text-slate-400">String</td>
                        <td className="py-2 px-2.5 text-slate-400">Permission identifier (e.g. `database.query`).</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-2.5 font-mono text-indigo-300">resourceType</td>
                        <td className="py-2 px-2.5 font-mono text-slate-400">String</td>
                        <td className="py-2 px-2.5 text-slate-400">Target type (e.g. `database`, `k8s_cluster`).</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-2.5 font-mono text-indigo-300">resourceId</td>
                        <td className="py-2 px-2.5 font-mono text-slate-400">String</td>
                        <td className="py-2 px-2.5 text-slate-400">Resource ID or SpEL (e.g. `#dbName`).</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-2.5 font-mono text-indigo-300">environment</td>
                        <td className="py-2 px-2.5 font-mono text-slate-400">String</td>
                        <td className="py-2 px-2.5 text-slate-400">Target environment or SpEL (e.g. `#env`).</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs text-slate-500 font-mono">
        AgentGuard • Open-Source Authorization & Governance for AI Agents • Apache-2.0
      </footer>
    </div>
  );
}
