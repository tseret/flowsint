import { useFlowStore } from '@/stores/flow-store'
import { DialogHeader, DialogFooter, Dialog, DialogContent, DialogTitle } from '../ui/dialog'
import { Button } from '../ui/button'
import { useState } from 'react'
import { EnricherParamSchemaItem } from '@/types'
import { Label } from '../ui/label'
import { Input } from '../ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select'
import KeySelector from '../keys/key-select'
import { type Key } from '@/types/key'
import { useQuery } from '@tanstack/react-query'
import { keyService } from '@/api/key-service'
import { flowService } from '@/api/flow-service'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/tabs'
import { MemoizedMarkdown } from '../chat/memoized-markdown'
import { cn } from '@/lib/utils'

const ParamsDialog = () => {
  const openParamsDialog = useFlowStore((s) => s.openParamsDialog)
  const setOpenParamsDialog = useFlowStore((s) => s.setOpenParamsDialog)
  const selectedNode = useFlowStore((s) => s.selectedNode)
  const updateNode = useFlowStore((s) => s.updateNode)
  const [params, setParams] = useState<Record<string, string>>({})
  const [saveAttempted, setSaveAttempted] = useState(false)

  // Reset drafts when opening or switching nodes, including after Cancel.
  const [previousSelection, setPreviousSelection] = useState({ selectedNode, openParamsDialog })
  if (
    selectedNode !== previousSelection.selectedNode ||
    openParamsDialog !== previousSelection.openParamsDialog
  ) {
    setPreviousSelection({ selectedNode, openParamsDialog })
    if (openParamsDialog) {
      setParams(selectedNode?.data.params ?? {})
      setSaveAttempted(false)
    }
  }

  // Fetch keys to convert between IDs and Key objects
  const { data: keys = [] } = useQuery<Key[]>({
    queryKey: ['keys'],
    queryFn: () => keyService.get()
  })
  const { data: materials, isFetching: refreshingSchema } = useQuery({
    queryKey: ['raw_material', selectedNode?.data.inputs.type],
    enabled: openParamsDialog && !!selectedNode?.data.inputs.type,
    queryFn: () =>
      flowService.getRawMaterialForType(selectedNode?.data.inputs.type.toLowerCase() || '')
  })
  const paramsSchema =
    materials?.items.find((item) => item.name === selectedNode?.data.name)?.params_schema ??
    selectedNode?.data.params_schema ??
    []

  const missingParams = paramsSchema.filter(
    (param: EnricherParamSchemaItem) =>
      param.required &&
      param.type !== 'vaultSecret' &&
      !params[param.name]?.trim() &&
      !param.default
  )

  const handleSave = () => {
    if (!selectedNode) return
    setSaveAttempted(true)
    if (refreshingSchema || missingParams.length) return
    const updatedNode = {
      ...selectedNode,
      data: {
        ...selectedNode.data,
        params,
        params_schema: paramsSchema
      }
    }
    updateNode(updatedNode)
    setOpenParamsDialog(false)
  }

  const renderField = (param: EnricherParamSchemaItem) => {
    if (param.type === 'vaultSecret') {
      return (
        <KeySelector
          onChange={(key) => setParams({ ...params, [param.name]: key.id })}
          value={keys.find((key) => key.id === params[param.name])}
        />
      )
    }

    if (param.type === 'select' && param.options?.length) {
      return (
        <Select
          value={params[param.name] || ''}
          onValueChange={(value) => setParams({ ...params, [param.name]: value })}
        >
          <SelectTrigger id={param.name} className="w-full">
            <SelectValue placeholder={`Select ${param.name}`} />
          </SelectTrigger>
          <SelectContent>
            {param.options.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )
    }

    return (
      <Input
        id={param.name}
        type={param.type}
        placeholder={param.default ?? param.name}
        value={params[param.name] || ''}
        aria-invalid={saveAttempted && missingParams.includes(param)}
        aria-describedby={
          saveAttempted && missingParams.includes(param) ? `${param.name}-error` : undefined
        }
        onChange={(e) => setParams({ ...params, [param.name]: e.target.value })}
      />
    )
  }

  if (!selectedNode) return

  return (
    <Dialog open={openParamsDialog} onOpenChange={setOpenParamsDialog}>
      <DialogContent className="!w-[90vw] !max-w-[900px] h-[90vh] overflow-y-auto flex flex-col">
        <DialogHeader>
          <DialogTitle>
            Configure <span className="text-primary">{selectedNode.data.class_name}</span>
          </DialogTitle>
          <div className={cn('justify-start', 'flex w-full')}>
            <div className={cn('w-full', 'p-3 rounded-xl max-w-full', 'flex flex-col gap-2')}>
              <div className="max-w-none">{selectedNode?.data.description?.toString()}</div>
            </div>
          </div>
        </DialogHeader>
        <Tabs defaultValue="parameters" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="parameters">Parameters</TabsTrigger>
            <TabsTrigger value="documentation">Documentation</TabsTrigger>
          </TabsList>
          <TabsContent value="parameters" className="space-y-4 mt-4">
            <div className="grid gap-4">
              {paramsSchema.map((param: EnricherParamSchemaItem) => (
                <div className="space-y-2" key={param.name}>
                  <div className="flex items-start flex-col">
                    <Label htmlFor={param.name} className="text-sm font-medium">
                      {param.name}
                      {param.required && <span className="text-destructive ml-1">*</span>}
                    </Label>
                    <p className="text-sm opacity-60">{param.description}</p>
                  </div>
                  {renderField(param)}
                  {saveAttempted && missingParams.includes(param) && (
                    <p id={`${param.name}-error`} role="alert" className="text-xs text-destructive">
                      {param.name} is required
                    </p>
                  )}
                </div>
              ))}
            </div>
          </TabsContent>
          <TabsContent value="documentation" className="space-y-4 mt-4">
            <div className="grid gap-4">
              <div className={cn('w-full', 'p-3 rounded-xl max-w-full', 'flex flex-col gap-2')}>
                <MemoizedMarkdown
                  id={selectedNode.id}
                  content={selectedNode?.data.documentation?.toString() ?? ''}
                />
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter className="mt-auto">
          <Button variant="outline" onClick={() => setOpenParamsDialog(false)}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={refreshingSchema}>
            Save configuration
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default ParamsDialog
