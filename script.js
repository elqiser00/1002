
function mergeFilters() {
    let filterText = document.getElementById("filterText").value;
    let filters = filterText.split("\n");
    let mergedFilters = filters.join("\n");
    document.getElementById("output").textContent = mergedFilters;
}

function downloadFile() {
    let mergedText = document.getElementById("output").textContent;
    let blob = new Blob([mergedText], { type: "text/plain" });
    let link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "merged_filters.txt";
    link.click();
}
