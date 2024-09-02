import React, { useState, useMemo } from 'react'
import { Input } from "./ui/input"
import { Button } from "./ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table"
import { AlertCircle, CheckCircle, ExternalLink, Download, Copy, Loader, AlertTriangle, ShieldCheck, TrendingUp, Info, Check } from 'lucide-react'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'
import { useDropzone } from 'react-dropzone'
import {
    useReactTable,
    getCoreRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    getFilteredRowModel,
    flexRender,
    ColumnDef,
} from '@tanstack/react-table'
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { motion, AnimatePresence } from 'framer-motion'
import { Toast } from "../components/ui/toast"

ChartJS.register(ArcElement, Tooltip, Legend)

type AuditResult = {
    name: string
    version: string
    vulnerability: string
    severity: 'low' | 'moderate' | 'high' | 'critical' | 'unknown'
    recommendation: string
    cvssScore?: number
    cvssVector?: string
    source?: number
    url?: string
    cwe?: string[]
}

type AuditSummary = {
    info: number
    low: number
    moderate: number
    high: number
    critical: number
    total: number
}

const NpmAuditDashboard: React.FC = () => {
    const [auditResults, setAuditResults] = useState<AuditResult[] | null>(null)
    const [auditSummary, setAuditSummary] = useState<AuditSummary | null>(null)
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [globalFilter, setGlobalFilter] = useState('')
    const [showToast, setShowToast] = useState(false)

    const columns: ColumnDef<AuditResult>[] = useMemo(
        () => [
            {
                header: 'Package',
                accessorKey: 'name',
            },
            {
                header: 'Version',
                accessorKey: 'version',
            },
            {
                header: 'Vulnerability',
                accessorKey: 'vulnerability',
                cell: ({ row }) => (
                    <div className="flex items-center">
                        {row.original.vulnerability === 'None' ? (
                            <CheckCircle className="text-green-500 mr-2" />
                        ) : (
                            <AlertCircle className="text-red-500 mr-2" />
                        )}
                        {row.original.vulnerability}
                        {row.original.url && (
                            <a href={row.original.url} target="_blank" rel="noopener noreferrer" className="ml-2">
                                <ExternalLink size={16} />
                            </a>
                        )}
                    </div>
                ),
            },
            {
                header: 'Severity',
                accessorKey: 'severity',
                cell: ({ row }) => (
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${row.original.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        row.original.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            row.original.severity === 'moderate' ? 'bg-yellow-100 text-yellow-800' :
                                row.original.severity === 'low' ? 'bg-green-100 text-green-800' :
                                    'bg-gray-100 text-gray-800'
                        }`}>
                        {row.original.severity}
                    </span>
                ),
            },
            {
                header: 'CVSS Score',
                accessorKey: 'cvssScore',
                cell: ({ row }) => (
                    row.original.cvssScore ? (
                        <div>
                            <p>{row.original.cvssScore.toFixed(1)}</p>
                            <p className="text-xs text-gray-500">{row.original.cvssVector}</p>
                        </div>
                    ) : 'N/A'
                ),
            },
            {
                header: 'Recommendation',
                accessorKey: 'recommendation',
            },
        ],
        []
    )

    const severityColors = {
        critical: 'bg-red-500',
        high: 'bg-orange-500',
        moderate: 'bg-yellow-500',
        low: 'bg-green-500',
        info: 'bg-blue-500'
    }

    const SeverityCard = ({ severity, count, total }) => {
        const percentage = total > 0 ? (count / total) * 100 : 0
        return (
            <motion.div
                className="bg-white rounded-lg shadow-md p-4 flex flex-col justify-between"
                whileHover={{ scale: 1.05 }}
                transition={{ type: "spring", stiffness: 300 }}
            >
                <div className="flex justify-between items-center mb-2">
                    <span className={`text-sm font-semibold ${severityColors[severity]} text-white px-2 py-1 rounded`}>
                        {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </span>
                    <span className="text-2xl font-bold text-gray-800">{count}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5">
                    <motion.div
                        className={`h-2.5 rounded-full ${severityColors[severity]}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${percentage}%` }}
                        transition={{ duration: 0.5, ease: "easeOut" }}
                    ></motion.div>
                </div>
            </motion.div>
        )
    }

    const table = useReactTable({
        data: auditResults || [],
        columns,
        getCoreRowModel: getCoreRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        state: {
            globalFilter,
        },
        onGlobalFilterChange: setGlobalFilter,
    })

    const onDrop = async (acceptedFiles: File[]) => {
        const file = acceptedFiles[0]
        if (file) {
            const reader = new FileReader()
            reader.onload = async (e) => {
                const content = e.target?.result as string
                await performAudit(content)
            }
            reader.readAsText(file)
        }
    }

    const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop })

    const performAudit = async (packageJsonContent: string) => {
        setIsLoading(true)
        setError(null)

        try {
            const { dependencies } = JSON.parse(packageJsonContent)
            const response = await fetch('/api/npm-audit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ dependencies }),
            })

            const data = await response.json()

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`)
            }

            setAuditResults(data.vulnerabilities || [])
            setAuditSummary(data.metadata?.vulnerabilities || null)
        } catch (error) {
            console.error('Error performing audit:', error)
            setError(`An error occurred while performing the audit: ${error instanceof Error ? error.message : String(error)}`)
        } finally {
            setIsLoading(false)
        }
    }

    const pieChartData = {
        labels: ['Critical', 'High', 'Moderate', 'Low', 'Info'],
        datasets: [
            {
                data: [
                    auditSummary?.critical || 0,
                    auditSummary?.high || 0,
                    auditSummary?.moderate || 0,
                    auditSummary?.low || 0,
                    auditSummary?.info || 0,
                ],
                backgroundColor: [
                    '#DC2626', // red-600
                    '#EA580C', // orange-600
                    '#CA8A04', // yellow-600
                    '#16A34A', // green-600
                    '#2563EB', // blue-600
                ],
            },
        ],
    }

    const generatePDFReport = () => {
        const doc = new jsPDF();

        // Set the document title and subtitle
        doc.setFontSize(20);
        doc.text('NPM Audit Report', 14, 22);

        doc.setFontSize(16);
        doc.text('Vulnerability Summary', 14, 32);

        // Data for the summary table
        const summaryData = [
            ['Total', auditSummary?.total?.toString() || '0'],
            ['Critical', auditSummary?.critical?.toString() || '0'],
            ['High', auditSummary?.high?.toString() || '0'],
            ['Moderate', auditSummary?.moderate?.toString() || '0'],
            ['Low', auditSummary?.low?.toString() || '0'],
            ['Info', auditSummary?.info?.toString() || '0'],
        ];

        // Draw the summary table
        autoTable(doc, {
            startY: 38, // Start position of the table on the Y-axis
            head: [['Severity', 'Count']],
            body: summaryData,
        });

        doc.setFontSize(16);
        doc.text('Vulnerability Details', 14, (doc as any).lastAutoTable.finalY + 10);

        // Data for the detailed vulnerabilities table
        const tableData =
            auditResults?.map((result) => [
                result.name,
                result.version,
                result.vulnerability,
                result.severity,
                result.cvssScore?.toString() || 'N/A',
                result.recommendation,
            ]) || [];

        // Draw the detailed vulnerabilities table
        autoTable(doc, {
            startY: (doc as any).lastAutoTable.finalY + 16, // Dynamic start position
            head: [['Package', 'Version', 'Vulnerability', 'Severity', 'CVSS Score', 'Recommendation']],
            body: tableData,
        });

        // Save the PDF
        doc.save('npm-audit-report.pdf');
    };

    const generateMarkdownReport = () => {
        let markdown = '# NPM Audit Report\n\n'

        markdown += '## Vulnerability Summary\n\n'
        markdown += `- Total: ${auditSummary?.total || 0}\n`
        markdown += `- Critical: ${auditSummary?.critical || 0}\n`
        markdown += `- High: ${auditSummary?.high || 0}\n`
        markdown += `- Moderate: ${auditSummary?.moderate || 0}\n`
        markdown += `- Low: ${auditSummary?.low || 0}\n`
        markdown += `- Info: ${auditSummary?.info || 0}\n\n`

        markdown += '## Vulnerability Details\n\n'
        markdown += '| Package | Version | Vulnerability | Severity | CVSS Score | Recommendation |\n'
        markdown += '|---------|---------|---------------|----------|------------|----------------|\n'

        auditResults?.forEach(result => {
            markdown += `| ${result.name} | ${result.version} | ${result.vulnerability} | ${result.severity} | ${result.cvssScore || 'N/A'} | ${result.recommendation} |\n`
        })

        return markdown
    }

    const copyMarkdownReport = () => {
        const markdown = generateMarkdownReport()
        navigator.clipboard.writeText(markdown)
            .then(() => {
                setShowToast(true)
                setTimeout(() => setShowToast(false), 3000)
            })
            .catch(err => console.error('Failed to copy report: ', err))
    }

    return (
        <div className="container mx-auto p-4 bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
            <motion.h1
                className="text-5xl font-bold mb-8 text-center text-gray-800"
                initial={{ opacity: 0, y: -50 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                NPM Audit Scanner
            </motion.h1>

            <motion.div
                {...getRootProps()}
                className="mb-8"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5 }}
            >
                <input {...getInputProps()} />
                <div className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-all duration-300 ${isDragActive ? 'border-primary bg-primary/10' : 'border-gray-300 hover:border-primary hover:bg-gray-50'
                    }`}>
                    {isDragActive ? (
                        <p className="text-primary text-xl font-semibold">Drop the package.json file here</p>
                    ) : (
                        <div>
                            <p className="text-gray-600 text-xl mb-2">Drag and drop a package.json file here</p>
                            <p className="text-gray-400">or click to select a file</p>
                        </div>
                    )}
                </div>
            </motion.div>

            {isLoading && (
                <motion.div
                    className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                >
                    <div className="bg-white p-8 rounded-lg shadow-xl flex flex-col items-center">
                        <Loader className="w-16 h-16 text-primary animate-spin mb-4" />
                        <p className="text-xl font-semibold text-gray-800">Performing audit...</p>
                    </div>
                </motion.div>
            )}

            <AnimatePresence>
                {error && (
                    <motion.div
                        className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded mb-8"
                        role="alert"
                        initial={{ opacity: 0, x: -50 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 50 }}
                    >
                        <p className="font-bold">Error</p>
                        <p>{error}</p>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {auditSummary && (
                    <motion.div
                        className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8"
                        initial={{ opacity: 0, y: 50 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5 }}
                    >
                        <div className="bg-white p-6 rounded-xl shadow-lg">
                            <h2 className="text-2xl font-bold mb-6 text-gray-800">Vulnerability Summary</h2>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-6">
                                <SeverityCard severity="critical" count={auditSummary.critical} total={auditSummary.total} />
                                <SeverityCard severity="high" count={auditSummary.high} total={auditSummary.total} />
                                <SeverityCard severity="moderate" count={auditSummary.moderate} total={auditSummary.total} />
                                <SeverityCard severity="low" count={auditSummary.low} total={auditSummary.total} />
                                <SeverityCard severity="info" count={auditSummary.info} total={auditSummary.total} />
                            </div>
                            <motion.div
                                className="flex items-center justify-between bg-gray-100 p-4 rounded-lg"
                                whileHover={{ scale: 1.02 }}
                                transition={{ type: "spring", stiffness: 400, damping: 10 }}
                            >
                                <div className="flex items-center">
                                    <AlertTriangle className="w-6 h-6 text-orange-500 mr-2" />
                                    <span className="text-lg font-semibold text-gray-700">Total Vulnerabilities</span>
                                </div>
                                <span className="text-2xl font-bold text-gray-800">{auditSummary.total}</span>
                            </motion.div>
                        </div>
                        <div className="bg-white p-6 rounded-xl shadow-lg">
                            <h2 className="text-2xl font-bold mb-6 text-gray-800">Audit Insights</h2>
                            <div className="space-y-4">
                                {auditSummary.total === 0 ? (
                                    <motion.div
                                        className="flex items-center p-4 bg-green-100 rounded-lg"
                                        whileHover={{ scale: 1.02 }}
                                        transition={{ type: "spring", stiffness: 400, damping: 10 }}
                                    >
                                        <ShieldCheck className="w-8 h-8 text-green-500 mr-4" />
                                        <p className="text-green-700 text-lg font-medium">No vulnerabilities found. Great job!</p>
                                    </motion.div>
                                ) : (
                                    <motion.div
                                        className="flex items-center p-4 bg-red-100 rounded-lg"
                                        whileHover={{ scale: 1.02 }}
                                        transition={{ type: "spring", stiffness: 400, damping: 10 }}
                                    >
                                        <AlertTriangle className="w-8 h-8 text-red-500 mr-4" />
                                        <p className="text-red-700 text-lg font-medium">Vulnerabilities detected. Action required.</p>
                                    </motion.div>
                                )}
                                {auditSummary.critical > 0 && (
                                    <motion.div
                                        className="flex items-center p-4 bg-red-50 rounded-lg"
                                        whileHover={{ scale: 1.02 }}
                                        transition={{ type: "spring", stiffness: 400, damping: 10 }}
                                    >
                                        <AlertTriangle className="w-6 h-6 text-red-500 mr-4" />
                                        <p className="text-red-700 font-medium">Critical vulnerabilities found! Immediate action recommended.</p>
                                    </motion.div>
                                )}
                                {auditSummary.high > 0 && (
                                    <motion.div
                                        className="flex items-center p-4 bg-orange-50 rounded-lg"
                                        whileHover={{ scale: 1.02 }}
                                        transition={{ type: "spring", stiffness: 400, damping: 10 }}
                                    >
                                        <TrendingUp className="w-6 h-6 text-orange-500 mr-4" />
                                        <p className="text-orange-700 font-medium">High severity vulnerabilities present. Address these soon.</p>
                                    </motion.div>
                                )}
                                {(auditSummary.moderate > 0 || auditSummary.low > 0) && (
                                    <motion.div
                                        className="flex items-center p-4 bg-yellow-50 rounded-lg"
                                        whileHover={{ scale: 1.02 }}
                                        transition={{ type: "spring", stiffness: 400, damping: 10 }}
                                    >
                                        <Info className="w-6 h-6 text-yellow-500 mr-4" />
                                        <p className="text-yellow-700 font-medium">Moderate and low severity issues exist. Plan to address these in future updates.</p>
                                    </motion.div>
                                )}
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {auditResults && auditResults.length > 0 && (
                    <motion.div
                        className="bg-white p-8 rounded-xl shadow-lg mb-8"
                        initial={{ opacity: 0, y: 50 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5 }}
                    >
                        <div className="flex flex-col md:flex-row justify-between items-center mb-6">
                            <h2 className="text-2xl font-bold text-gray-800 mb-4 md:mb-0">Vulnerability Details</h2>
                            <div className="space-x-4">
                                <Button onClick={generatePDFReport} className="bg-primary hover:bg-primary/90 transition-colors duration-200">
                                    <Download className="mr-2 h-4 w-4" /> Export PDF
                                </Button>
                                <Button onClick={copyMarkdownReport} className="bg-secondary hover:bg-secondary/90 transition-colors duration-200">
                                    <Copy className="mr-2 h-4 w-4" /> Copy Markdown
                                </Button>
                            </div>
                        </div>
                        <Input
                            placeholder="Search vulnerabilities..."
                            value={globalFilter ?? ''}
                            onChange={(e) => setGlobalFilter(e.target.value)}
                            className="mb-6"
                        />
                        <div className="overflow-x-auto">
                            <Table>
                                <TableHeader>
                                    {table.getHeaderGroups().map((headerGroup) => (
                                        <TableRow key={headerGroup.id}>
                                            {headerGroup.headers.map((header) => (
                                                <TableHead key={header.id} className="text-gray-700">
                                                    {flexRender(
                                                        header.column.columnDef.header,
                                                        header.getContext()
                                                    )}
                                                </TableHead>
                                            ))}
                                        </TableRow>
                                    ))}
                                </TableHeader>
                                <TableBody>
                                    {table.getRowModel().rows.map((row) => (
                                        <TableRow key={row.id} className="hover:bg-gray-50 transition-colors duration-200">
                                            {row.getVisibleCells().map((cell) => (
                                                <TableCell key={cell.id}>
                                                    {flexRender(
                                                        cell.column.columnDef.cell,
                                                        cell.getContext()
                                                    )}
                                                </TableCell>
                                            ))}
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                        <div className="flex items-center justify-between mt-6">
                            <div className="flex items-center gap-2">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => table.previousPage()}
                                    disabled={!table.getCanPreviousPage()}
                                    className="text-gray-600 hover:text-gray-800"
                                >
                                    Previous
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => table.nextPage()}
                                    disabled={!table.getCanNextPage()}
                                    className="text-gray-600 hover:text-gray-800"
                                >
                                    Next
                                </Button>
                            </div>
                            <p className="text-sm text-gray-600">
                                Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
                            </p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {auditResults && auditResults.length === 0 && !error && (
                    <motion.div
                        className="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 rounded mb-8"
                        role="alert"
                        initial={{ opacity: 0, x: -50 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 50 }}
                    >
                        <p className="font-bold">Success</p>
                        <p>No vulnerabilities found!</p>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {showToast && (
                    <motion.div
                        initial={{ opacity: 0, y: 50 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 50 }}
                        className="fixed bottom-4 right-4"
                    >
                        <Toast message="Markdown copied to clipboard!" />
                    </motion.div>
                )}
            </AnimatePresence>
            <footer className="mt-8 py-4 text-center bg-gray-100 text-gray-600">
                <p>
                    Built with ❤️ by{' '}
                    <a
                        href="https://www.linkedin.com/in/bohr/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-500 hover:underline"
                    >
                        Bour Abdelhadi
                    </a>{' '}
                    and the help of{' '}
                    <a
                        href="https://claude.ai/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-500 hover:underline"
                    >
                        Claude
                    </a>
                </p>
            </footer>
        </div>
    )
}

export default NpmAuditDashboard