import { Component, Input, OnInit, OnDestroy, ViewChild, ElementRef, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CallChain } from '../../models/scan.model';
import cytoscape, { Core, NodeSingular } from 'cytoscape';
// @ts-ignore
import dagre from 'cytoscape-dagre';

interface NodeData {
  id: string;
  label: string;
  type: 'entry' | 'intermediate' | 'sink';
  fileName: string;
  lineNumber: number;
  methodName: string;
  className: string;
  snippet: string;
}

@Component({
  selector: 'app-attack-flow-diagram',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './attack-flow-diagram.component.html',
  styleUrls: ['./attack-flow-diagram.component.css']
})
export class AttackFlowDiagramComponent implements OnInit, AfterViewInit, OnDestroy {
  @Input() callChain: CallChain | null = null;
  @Input() chainIndex: number = 0;
  @ViewChild('cytoscapeContainer', { static: false }) cytoscapeContainer!: ElementRef;

  cy: Core | null = null;
  selectedNode: NodeData | null = null;
  isExporting: boolean = false;

  ngOnInit(): void {
    // Register dagre layout extension
    cytoscape.use(dagre);
  }

  ngAfterViewInit(): void {
    if (this.callChain) {
      this.initializeDiagram();
    }
  }

  ngOnDestroy(): void {
    if (this.cy) {
      this.cy.destroy();
    }
  }

  /**
   * Initializes the Cytoscape diagram
   */
  private initializeDiagram(): void {
    if (!this.callChain || !this.cytoscapeContainer) {
      return;
    }

    const elements = this.buildGraphElements();

    this.cy = cytoscape({
      container: this.cytoscapeContainer.nativeElement,
      elements: elements,
      style: this.getCytoscapeStyles(),
      layout: {
        name: 'dagre',
        rankDir: 'TB', // Top to bottom
        nodeSep: 80,
        rankSep: 100,
        padding: 30
      } as any,
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.2
    });

    // Add click handler for nodes
    this.cy.on('tap', 'node', (event) => {
      const node = event.target;
      this.onNodeClick(node);
    });

    // Add hover effects
    this.cy.on('mouseover', 'node', (event) => {
      const node = event.target;
      node.addClass('hover');
      document.body.style.cursor = 'pointer';
    });

    this.cy.on('mouseout', 'node', (event) => {
      const node = event.target;
      node.removeClass('hover');
      document.body.style.cursor = 'default';
    });

    // Fit the diagram to the container
    setTimeout(() => {
      if (this.cy) {
        this.cy.fit(undefined, 50);
      }
    }, 100);
  }

  /**
   * Builds graph elements (nodes and edges) from the call chain
   */
  private buildGraphElements(): any[] {
    if (!this.callChain) {
      return [];
    }

    const nodes: any[] = [];
    const edges: any[] = [];
    const steps = this.callChain.steps;

    steps.forEach((step, index) => {
      // Determine node type
      let nodeType: 'entry' | 'intermediate' | 'sink';
      if (index === 0) {
        nodeType = 'entry';
      } else if (index === steps.length - 1) {
        nodeType = 'sink';
      } else {
        nodeType = 'intermediate';
      }

      // Create node
      const nodeId = `step-${index}`;
      nodes.push({
        data: {
          id: nodeId,
          label: `${step.className}.${step.methodName}`,
          type: nodeType,
          fileName: step.fileName,
          lineNumber: step.lineNumber,
          methodName: step.methodName,
          className: step.className,
          snippet: step.snippet,
          stepNumber: index + 1
        }
      });

      // Create edge to next node
      if (index < steps.length - 1) {
        edges.push({
          data: {
            id: `edge-${index}`,
            source: nodeId,
            target: `step-${index + 1}`
          }
        });
      }
    });

    return [...nodes, ...edges];
  }

  /**
   * Returns Cytoscape style definitions
   */
  private getCytoscapeStyles(): any[] {
    return [
      // Node styles
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'text-max-width': '200px',
          'font-size': '12px',
          'font-weight': '600',
          'color': '#1f2937',
          'background-color': '#f3f4f6',
          'border-width': 3,
          'border-color': '#9ca3af',
          'width': 'label',
          'height': 'label',
          'padding': '20px',
          'shape': 'roundrectangle',
          'text-margin-y': -5
        }
      },
      // Entry point node (red)
      {
        selector: 'node[type = "entry"]',
        style: {
          'background-color': '#fee2e2',
          'border-color': '#dc2626',
          'border-width': 4,
          'font-weight': '700'
        }
      },
      // Vulnerable sink node (dark red)
      {
        selector: 'node[type = "sink"]',
        style: {
          'background-color': '#fecaca',
          'border-color': '#991b1b',
          'border-width': 4,
          'font-weight': '700'
        }
      },
      // Intermediate nodes (grey)
      {
        selector: 'node[type = "intermediate"]',
        style: {
          'background-color': '#f9fafb',
          'border-color': '#6b7280',
          'border-width': 3
        }
      },
      // Selected node
      {
        selector: 'node.selected',
        style: {
          'border-color': '#6366f1',
          'border-width': 5,
          'background-color': '#eef2ff',
          'box-shadow': '0 0 20px #6366f1'
        }
      },
      // Hover effect
      {
        selector: 'node.hover',
        style: {
          'border-color': '#8b5cf6',
          'background-color': '#ede9fe'
        }
      },
      // Edge styles
      {
        selector: 'edge',
        style: {
          'width': 3,
          'line-color': '#9ca3af',
          'target-arrow-color': '#9ca3af',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 1.5
        }
      },
      // Selected edge
      {
        selector: 'edge.selected',
        style: {
          'line-color': '#6366f1',
          'target-arrow-color': '#6366f1',
          'width': 4
        }
      }
    ];
  }

  /**
   * Handles node click events
   */
  private onNodeClick(node: NodeSingular): void {
    // Remove previous selection
    if (this.cy) {
      this.cy.elements().removeClass('selected');
    }

    // Add selection to clicked node and its edges
    node.addClass('selected');
    node.connectedEdges().addClass('selected');

    // Update selected node data
    const data = node.data();
    this.selectedNode = {
      id: data.id,
      label: data.label,
      type: data.type,
      fileName: data.fileName,
      lineNumber: data.lineNumber,
      methodName: data.methodName,
      className: data.className,
      snippet: data.snippet
    };
  }

  /**
   * Closes the node detail panel
   */
  closeNodeDetails(): void {
    this.selectedNode = null;
    if (this.cy) {
      this.cy.elements().removeClass('selected');
    }
  }

  /**
   * Resets the diagram zoom and position
   */
  resetView(): void {
    if (this.cy) {
      this.cy.fit(undefined, 50);
    }
  }

  /**
   * Exports the diagram as PNG
   */
  async exportToPng(): Promise<void> {
    if (!this.cy) {
      return;
    }

    this.isExporting = true;

    try {
      // Get PNG data from Cytoscape
      const pngData: string | Blob = this.cy.png({
        output: 'blob',
        bg: '#ffffff',
        full: true,
        scale: 3 // Higher resolution
      });

      let blob: Blob;
      
      if (pngData instanceof Blob) {
        // Already a Blob
        blob = pngData;
      } else {
        // pngData is a string (base64)
        const dataString = pngData as string;
        const parts = dataString.split(',');
        const byteString = atob(parts[1]);
        const mimeString = parts[0].split(':')[1].split(';')[0];
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        for (let i = 0; i < byteString.length; i++) {
          ia[i] = byteString.charCodeAt(i);
        }
        blob = new Blob([ab], { type: mimeString });
      }

      // Create download link
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `attack-flow-chain-${this.chainIndex + 1}.png`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      console.log('Diagram exported successfully');
    } catch (error) {
      console.error('Error exporting diagram:', error);
      alert('Failed to export diagram. Please try again.');
    } finally {
      this.isExporting = false;
    }
  }

  /**
   * Returns the node type label for display
   */
  getNodeTypeLabel(type: string): string {
    switch (type) {
      case 'entry':
        return 'Entry Point';
      case 'sink':
        return 'Vulnerable Sink';
      case 'intermediate':
        return 'Intermediate Step';
      default:
        return 'Unknown';
    }
  }

  /**
   * Returns the CSS class for node type badge
   */
  getNodeTypeBadgeClass(type: string): string {
    switch (type) {
      case 'entry':
        return 'badge-entry';
      case 'sink':
        return 'badge-sink';
      case 'intermediate':
        return 'badge-intermediate';
      default:
        return '';
    }
  }
}