$tableName = "GovernanceBedrockStack-ToolModelRegistryTableADE03FFA-117P7N739ZFZG"
Write-Output "Table: $tableName"

$items = @(
    '{"entry_id":{"S":"tc-read-pipeline"},"category":{"S":"tool_connector"},"name":{"S":"ReadPipelineStatus"},"version":{"S":"*"},"approval_status":{"S":"approved"},"approved_by":{"S":"governance-admin"},"description":{"S":"Read pipeline status action group"},"registered_at":{"S":"2025-01-15T10:30:00Z"}}',
    '{"entry_id":{"S":"tc-propose-changes"},"category":{"S":"tool_connector"},"name":{"S":"ProposeChanges"},"version":{"S":"*"},"approval_status":{"S":"approved"},"approved_by":{"S":"governance-admin"},"description":{"S":"Propose changes action group"},"registered_at":{"S":"2025-01-15T10:30:00Z"}}',
    '{"entry_id":{"S":"tc-staging-deploy"},"category":{"S":"tool_connector"},"name":{"S":"StagingDeployment"},"version":{"S":"*"},"approval_status":{"S":"approved"},"approved_by":{"S":"governance-admin"},"description":{"S":"Staging deployment action group"},"registered_at":{"S":"2025-01-15T10:30:00Z"}}',
    '{"entry_id":{"S":"tc-production-deploy"},"category":{"S":"tool_connector"},"name":{"S":"ProductionDeployment"},"version":{"S":"*"},"approval_status":{"S":"approved"},"approved_by":{"S":"governance-admin"},"description":{"S":"Production deployment action group"},"registered_at":{"S":"2025-01-15T10:30:00Z"}}'
)

$i = 0
foreach ($item in $items) {
    $file = "seed_item_$i.json"
    [System.IO.File]::WriteAllText((Join-Path $PWD $file), $item)
    aws dynamodb put-item --table-name $tableName --item file://$file
    if ($LASTEXITCODE -eq 0) {
        Write-Output "OK: inserted item $i"
    } else {
        Write-Output "FAILED: item $i"
    }
    Remove-Item $file
    $i++
}

Write-Output "Done"
