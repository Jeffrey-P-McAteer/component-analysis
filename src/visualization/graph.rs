#[cfg(feature = "gui")]
use crate::types::{Component, Relationship, ComponentType};
#[cfg(feature = "gui")]
use egui::{Ui, Pos2, Vec2, Rect, Color32, Stroke, Rounding};
#[cfg(feature = "gui")]
use std::collections::{HashMap, HashSet, BTreeMap};

#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub component: Component,
    pub position: Pos2,
    pub size: Vec2,
    pub selected: bool,
    pub hovered: bool,
    pub dragging: bool,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub id: String,
    pub relationship: Relationship,
    pub from_pos: Pos2,
    pub to_pos: Pos2,
    pub selected: bool,
    pub edge_type: EdgeType,
    pub visible: bool,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeType {
    Normal,
    ReadPath,
    WritePath,
    BidirectionalPath,
}

#[cfg(feature = "gui")]
pub struct ComponentGraph {
    pub nodes: BTreeMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub layout: GraphLayout,
    pub viewport: Rect,
    pub zoom: f32,
    pub pan_offset: Vec2,
    pub selection: HashSet<String>,
    pub path_visualization_mode: bool,
    pub highlighted_components: HashSet<String>,
    pub stable_paths: bool,
    pub read_paths: Vec<Vec<String>>,
    pub write_paths: Vec<Vec<String>>,
    pub dragging_node: Option<String>,
    pub drag_start_pos: Option<Pos2>,
    pub show_all_connections: bool,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
pub enum GraphLayout {
    Force,
    Hierarchical,
    Circular,
    Grid,
}

#[cfg(feature = "gui")]
impl ComponentGraph {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            layout: GraphLayout::Force,
            viewport: Rect::NOTHING,
            zoom: 1.0,
            pan_offset: Vec2::ZERO,
            selection: HashSet::new(),
            path_visualization_mode: false,
            highlighted_components: HashSet::new(),
            stable_paths: true,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            dragging_node: None,
            drag_start_pos: None,
            show_all_connections: true,
        }
    }

    pub fn add_component(&mut self, component: Component) {
        let node = GraphNode {
            id: component.id.clone(),
            position: Pos2::new(0.0, 0.0), // Will be set by layout
            size: Self::calculate_node_size(&component),
            selected: false,
            hovered: false,
            dragging: false,
            component,
        };
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_relationship(&mut self, relationship: Relationship) {
        if let (Some(from_node), Some(to_node)) = (
            self.nodes.get(&relationship.source_id),
            self.nodes.get(&relationship.target_id)
        ) {
            let edge = GraphEdge {
                id: format!("{}_{}", relationship.source_id, relationship.target_id),
                from_pos: from_node.position,
                to_pos: to_node.position,
                selected: false,
                edge_type: EdgeType::Normal,
                visible: true,
                relationship,
            };
            self.edges.push(edge);
        }
    }

    pub fn set_layout(&mut self, layout: GraphLayout) {
        self.layout = layout;
        self.apply_layout();
    }

    pub fn apply_layout(&mut self) {
        match self.layout {
            GraphLayout::Force => self.apply_force_layout(),
            GraphLayout::Hierarchical => self.apply_hierarchical_layout(),
            GraphLayout::Circular => self.apply_circular_layout(),
            GraphLayout::Grid => self.apply_grid_layout(),
        }
        self.update_edge_positions();
    }

    fn apply_force_layout(&mut self) {
        let node_count = self.nodes.len();
        if node_count == 0 {
            return;
        }

        let center = Pos2::new(400.0, 300.0);
        let radius = 200.0;

        // Simple circular arrangement as a starting point for force layout
        let mut angle: f32 = 0.0;
        let angle_step = 2.0 * std::f32::consts::PI / node_count as f32;

        for node in self.nodes.values_mut() {
            node.position = center + Vec2::new(
                radius * angle.cos(),
                radius * angle.sin(),
            );
            angle += angle_step;
        }

        // Apply force-directed algorithm (simplified)
        for _ in 0..50 {
            self.apply_forces();
        }
    }

    fn apply_forces(&mut self) {
        let mut forces: HashMap<String, Vec2> = HashMap::new();
        
        // Repulsion forces between nodes (sorted for stable behavior)
        let mut nodes: Vec<_> = self.nodes.values().collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        for (i, node1) in nodes.iter().enumerate() {
            let mut force = Vec2::ZERO;
            
            for (j, node2) in nodes.iter().enumerate() {
                if i != j {
                    let diff = node1.position - node2.position;
                    let distance = diff.length().max(1.0);
                    let repulsion = 1000.0 / (distance * distance);
                    force += diff.normalized() * repulsion;
                }
            }
            forces.insert(node1.id.clone(), force);
        }

        // Attraction forces along edges
        for edge in &self.edges {
            if let (Some(from_node), Some(to_node)) = (
                self.nodes.get(&edge.relationship.source_id),
                self.nodes.get(&edge.relationship.target_id)
            ) {
                let diff = to_node.position - from_node.position;
                let distance = diff.length().max(1.0);
                let attraction = distance * 0.01;
                let attraction_force = diff.normalized() * attraction;

                forces.entry(from_node.id.clone()).and_modify(|f| *f += attraction_force).or_insert(attraction_force);
                forces.entry(to_node.id.clone()).and_modify(|f| *f -= attraction_force).or_insert(-attraction_force);
            }
        }

        // Apply forces with damping (sorted by ID for consistent application)
        let mut sorted_forces: Vec<_> = forces.into_iter().collect();
        sorted_forces.sort_by(|a, b| a.0.cmp(&b.0));
        
        for (id, force) in sorted_forces {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.position += force * 0.1; // Damping factor
            }
        }
    }

    fn apply_hierarchical_layout(&mut self) {
        let mut levels: HashMap<String, usize> = HashMap::new();
        let mut level_nodes: Vec<Vec<String>> = Vec::new();

        // Find root nodes (components with no incoming edges)
        let mut incoming_counts: HashMap<String, usize> = HashMap::new();
        for node_id in self.nodes.keys() {
            incoming_counts.insert(node_id.clone(), 0);
        }
        for edge in &self.edges {
            *incoming_counts.entry(edge.relationship.target_id.clone()).or_insert(0) += 1;
        }

        // BFS to assign levels
        let mut current_level = 0;
        let mut queue: Vec<_> = incoming_counts.iter()
            .filter(|(_, &count)| count == 0)
            .map(|(id, _)| id.clone())
            .collect();

        while !queue.is_empty() {
            if level_nodes.len() <= current_level {
                level_nodes.push(Vec::new());
            }
            
            let mut next_queue = Vec::new();
            
            for node_id in queue {
                levels.insert(node_id.clone(), current_level);
                level_nodes[current_level].push(node_id.clone());

                // Add children to next level
                for edge in &self.edges {
                    if edge.relationship.source_id == node_id {
                        let target = &edge.relationship.target_id;
                        if !levels.contains_key(target) {
                            next_queue.push(target.clone());
                        }
                    }
                }
            }

            queue = next_queue;
            current_level += 1;
        }

        // Position nodes
        let level_height = 100.0;
        let node_spacing = 150.0;

        for (level_idx, level_node_ids) in level_nodes.iter().enumerate() {
            let y = level_idx as f32 * level_height + 50.0;
            let total_width = (level_node_ids.len().saturating_sub(1)) as f32 * node_spacing;
            let start_x = 400.0 - total_width / 2.0;

            for (node_idx, node_id) in level_node_ids.iter().enumerate() {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    node.position = Pos2::new(start_x + node_idx as f32 * node_spacing, y);
                }
            }
        }
    }

    fn apply_circular_layout(&mut self) {
        let node_count = self.nodes.len();
        if node_count == 0 {
            return;
        }

        let center = Pos2::new(400.0, 300.0);
        let radius = 200.0;
        let mut angle: f32 = 0.0;
        let angle_step = 2.0 * std::f32::consts::PI / node_count as f32;

        for node in self.nodes.values_mut() {
            node.position = center + Vec2::new(
                radius * angle.cos(),
                radius * angle.sin(),
            );
            angle += angle_step;
        }
    }

    fn apply_grid_layout(&mut self) {
        let node_count = self.nodes.len();
        if node_count == 0 {
            return;
        }

        let cols = (node_count as f32).sqrt().ceil() as usize;
        let cell_width = 150.0;
        let cell_height = 100.0;

        for (idx, node) in self.nodes.values_mut().enumerate() {
            let row = idx / cols;
            let col = idx % cols;
            node.position = Pos2::new(
                50.0 + col as f32 * cell_width,
                50.0 + row as f32 * cell_height,
            );
        }
    }

    fn update_edge_positions(&mut self) {
        for edge in &mut self.edges {
            if let (Some(from_node), Some(to_node)) = (
                self.nodes.get(&edge.relationship.source_id),
                self.nodes.get(&edge.relationship.target_id)
            ) {
                edge.from_pos = from_node.position + from_node.size * 0.5;
                edge.to_pos = to_node.position + to_node.size * 0.5;
            }
        }
    }

    fn calculate_node_size(component: &Component) -> Vec2 {
        let base_size = match component.component_type {
            ComponentType::Binary => Vec2::new(80.0, 60.0),
            ComponentType::Function => Vec2::new(60.0, 40.0),
            ComponentType::Instruction => Vec2::new(40.0, 30.0),
            ComponentType::Process => Vec2::new(100.0, 70.0),
            ComponentType::Host => Vec2::new(120.0, 80.0),
            ComponentType::Network => Vec2::new(90.0, 50.0),
        };

        // Adjust size based on name length
        let text_width = component.name.len() as f32 * 8.0;
        Vec2::new(base_size.x.max(text_width + 20.0), base_size.y)
    }

    pub fn render(&mut self, ui: &mut Ui) {
        let available_rect = ui.available_rect_before_wrap();
        self.viewport = available_rect;

        let response = ui.allocate_response(available_rect.size(), egui::Sense::click_and_drag());

        // Handle pan and zoom (only when not dragging nodes)
        let is_dragging_nodes = self.dragging_node.is_some();
        if response.dragged() && !is_dragging_nodes {
            let new_pan = self.pan_offset + response.drag_delta() / self.zoom;
            // Limit pan to reasonable bounds
            self.pan_offset = Vec2::new(
                new_pan.x.clamp(-2000.0, 2000.0),
                new_pan.y.clamp(-2000.0, 2000.0),
            );
        }
        
        // Handle zoom with mouse wheel
        ui.input(|i| {
            let scroll_delta = i.raw_scroll_delta.y;
            if scroll_delta != 0.0 {
                let zoom_factor = 1.0 + scroll_delta * 0.001;
                let new_zoom = (self.zoom * zoom_factor).clamp(0.1, 5.0);
                
                // Zoom towards mouse position
                if let Some(pointer_pos) = i.pointer.hover_pos() {
                    let local_pos = pointer_pos - self.viewport.min;
                    let world_pos = (local_pos - self.pan_offset * self.zoom) / self.zoom;
                    
                    self.zoom = new_zoom;
                    self.pan_offset = (local_pos - world_pos * self.zoom) / self.zoom;
                } else {
                    self.zoom = new_zoom;
                }
            }
        });
        
        // Handle reset zoom/pan with double-click
        if response.double_clicked() {
            self.zoom = 1.0;
            self.pan_offset = Vec2::ZERO;
        }

        // Collect node data and drawing info (sorted by ID for stable ordering)
        let mut sorted_nodes: Vec<_> = self.nodes.values().collect();
        sorted_nodes.sort_by(|a, b| a.id.cmp(&b.id));
        
        let node_data: Vec<_> = sorted_nodes.iter().map(|node| {
            let pos = self.transform_position(node.position);
            let size = node.size * self.zoom;
            let rect = Rect::from_min_size(pos, size);
            
            (
                node.id.clone(),
                rect,
                node.selected,
                node.hovered,
                node.dragging,
                node.component.component_type.clone(),
                node.component.name.clone(),
            )
        }).collect();

        // Sort edges by ID for stable ordering
        let mut sorted_edges: Vec<_> = self.edges.iter()
            .filter(|edge| edge.visible)
            .collect();
        sorted_edges.sort_by(|a, b| a.id.cmp(&b.id));
        
        let edge_data: Vec<_> = sorted_edges.iter()
            .filter(|edge| self.show_all_connections || edge.visible)
            .map(|edge| {
                let from = self.transform_position(edge.from_pos);
                let to = self.transform_position(edge.to_pos);
                let color = if edge.selected {
                    Color32::from_rgb(255, 100, 100)
                } else {
                    match edge.edge_type {
                        EdgeType::ReadPath => Color32::from_rgb(50, 150, 255), // Blue for read paths
                        EdgeType::WritePath => Color32::from_rgb(255, 200, 50), // Yellow for write paths
                        EdgeType::BidirectionalPath => Color32::from_rgb(150, 255, 150), // Green for bidirectional
                        EdgeType::Normal => Color32::from_rgb(100, 100, 100), // Gray for normal
                    }
                };
                (from, to, color, edge.edge_type.clone())
            }).collect();

        // Draw everything
        let painter = ui.painter();
        
        // Draw edges
        for (from, to, color, edge_type) in edge_data {
            let stroke_width = match edge_type {
                EdgeType::ReadPath | EdgeType::WritePath => 3.0, // Thicker for highlighted paths
                EdgeType::BidirectionalPath => 4.0,
                EdgeType::Normal => 2.0,
            };
            painter.arrow(from, to - from, Stroke::new(stroke_width, color));
        }
        
        // Draw nodes first
        for (_, rect, selected, hovered, dragging, component_type, name) in &node_data {
            let mut color = self.get_node_color(component_type);
            
            // Slightly transparent when dragging
            if *dragging {
                color = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 200);
            }
            
            let stroke_color = if *dragging {
                Color32::from_rgb(255, 100, 100)  // Red when dragging
            } else if *selected {
                Color32::from_rgb(255, 200, 0)
            } else if *hovered {
                Color32::from_rgb(200, 200, 200)
            } else {
                Color32::from_rgb(100, 100, 100)
            };
            
            let stroke_width = if *dragging { 3.0 } else { 2.0 };

            // Draw node
            painter.rect(*rect, Rounding::same(5.0), color, Stroke::new(stroke_width, stroke_color));

            // Draw text
            let text_pos = rect.center();
            painter.text(
                text_pos,
                egui::Align2::CENTER_CENTER,
                name,
                egui::FontId::default(),
                Color32::BLACK,
            );
        }

        // Now handle interactions separately
        let mut node_interactions = Vec::new();
        for (node_id, rect, _, _, _, _, _) in node_data {
            let node_response = ui.allocate_rect(rect, egui::Sense::click_and_drag());
            node_interactions.push((node_id, node_response.hovered(), node_response.clicked(), 
                                  node_response.drag_started(), node_response.dragged(), 
                                  node_response.drag_stopped(), node_response.drag_delta()));
        }
        
        // Apply interactions
        let mut needs_edge_update = false;
        let mut needs_group_movement = false;
        let mut group_movement = Vec2::ZERO;
        
        for (node_id, is_hovered, was_clicked, drag_started, is_dragging, drag_released, drag_delta) in node_interactions {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.hovered = is_hovered;
                
                // Handle drag start
                if drag_started {
                    self.dragging_node = Some(node_id.clone());
                    self.drag_start_pos = Some(node.position);
                    node.dragging = true;
                }
                
                // Handle dragging
                if is_dragging && self.dragging_node.as_ref() == Some(&node_id) {
                    // Check if Ctrl is held for group movement
                    let ctrl_held = ui.input(|i| i.modifiers.ctrl);
                    let movement = drag_delta / self.zoom;
                    
                    if ctrl_held && self.path_visualization_mode {
                        // Store the movement to apply after releasing the borrow
                        node.position += movement;
                        needs_edge_update = true;
                        // Mark that we need to move the group after this loop
                        needs_group_movement = true;
                        group_movement = movement;
                    } else {
                        // Move only the dragged node
                        node.position += movement;
                        needs_edge_update = true;
                    }
                }
                
                // Handle drag end
                if drag_released && self.dragging_node.as_ref() == Some(&node_id) {
                    self.dragging_node = None;
                    self.drag_start_pos = None;
                    node.dragging = false;
                }
                
                // Only handle clicks if not dragging
                if was_clicked && !node.dragging {
                    self.handle_node_selection(&node_id);
                }
            }
        }
        
        // Apply group movement after all node interactions are processed
        if needs_group_movement {
            // Move other highlighted components (excluding the one already moved)
            let dragged_node_id = self.dragging_node.clone();
            for comp_id in &self.highlighted_components {
                if dragged_node_id.as_ref() != Some(comp_id) {
                    if let Some(node) = self.nodes.get_mut(comp_id) {
                        node.position += group_movement;
                    }
                }
            }
        }
        
        // Update edge positions after all interactions are processed
        if needs_edge_update {
            self.update_edge_positions();
        }
    }

    fn transform_position(&self, pos: Pos2) -> Pos2 {
        (pos + self.pan_offset) * self.zoom + self.viewport.min.to_vec2()
    }

    fn get_node_color(&self, component_type: &ComponentType) -> Color32 {
        match component_type {
            ComponentType::Binary => Color32::from_rgb(100, 150, 255),
            ComponentType::Function => Color32::from_rgb(150, 255, 150),
            ComponentType::Instruction => Color32::from_rgb(255, 255, 150),
            ComponentType::Process => Color32::from_rgb(255, 150, 150),
            ComponentType::Host => Color32::from_rgb(200, 150, 255),
            ComponentType::Network => Color32::from_rgb(150, 255, 255),
        }
    }

    pub fn clear_selection(&mut self) {
        for node in self.nodes.values_mut() {
            node.selected = false;
            node.dragging = false;
        }
        self.selection.clear();
        self.highlighted_components.clear();
        self.dragging_node = None;
        self.drag_start_pos = None;
        
        // Clear path visualization when selection is cleared
        if self.path_visualization_mode {
            self.clear_path_visualization();
        }
    }
    
    /// Handles node selection with proper multi-selection support
    fn handle_node_selection(&mut self, node_id: &str) {
        // Toggle selection for multi-select
        if self.selection.contains(node_id) {
            self.selection.remove(node_id);
            self.highlighted_components.remove(node_id);
            if let Some(node) = self.nodes.get_mut(node_id) {
                node.selected = false;
            }
        } else {
            self.selection.insert(node_id.to_string());
            self.highlighted_components.insert(node_id.to_string());
            if let Some(node) = self.nodes.get_mut(node_id) {
                node.selected = true;
            }
        }
        
        // Update path visualization for all selected components
        self.update_path_visualization_for_selection();
    }
    
    /// Updates path visualization for all currently selected components
    fn update_path_visualization_for_selection(&mut self) {
        if !self.selection.is_empty() {
            self.path_visualization_mode = true;
            
            // Reset all edges to normal and invisible for clean state
            for edge in &mut self.edges {
                edge.edge_type = EdgeType::Normal;
                edge.visible = false;
            }
            
            // Clear previous paths
            self.read_paths.clear();
            self.write_paths.clear();
            
            // For each selected component, find its relationships
            // We'll gather all relationships first to avoid database calls in a loop
            let all_relationships = self.get_all_current_relationships();
            let selected_components: Vec<String> = self.selection.iter().cloned().collect();
            
            for component_id in &selected_components {
                self.add_component_paths(component_id, &all_relationships);
            }
            
            // Apply the collected paths
            self.apply_collected_paths();
        } else {
            self.clear_path_visualization();
        }
    }

    pub fn get_selected_components(&self) -> Vec<&Component> {
        self.selection.iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| &node.component)
            .collect()
    }

    pub fn highlight_component_paths(&mut self, component_id: &str, relationships: &[Relationship]) {
        // Clear existing selection and add this component
        self.selection.clear();
        self.selection.insert(component_id.to_string());
        self.highlighted_components.clear();
        self.highlighted_components.insert(component_id.to_string());
        
        // Update the node selection state
        for node in self.nodes.values_mut() {
            node.selected = false;
        }
        if let Some(node) = self.nodes.get_mut(component_id) {
            node.selected = true;
        }
        
        // Use the stable multi-selection path update
        self.path_visualization_mode = true;
        self.reset_edges_for_path_visualization();
        self.read_paths.clear();
        self.write_paths.clear();
        
        self.add_component_paths(component_id, relationships);
        self.apply_collected_paths();
    }

    pub fn clear_path_visualization(&mut self) {
        self.path_visualization_mode = false;
        self.highlighted_components.clear();
        self.read_paths.clear();
        self.write_paths.clear();
        
        // Reset all edges to normal and visible
        for edge in &mut self.edges {
            edge.edge_type = EdgeType::Normal;
            edge.visible = true;
        }
        
        // Clear node selections and drag state
        for node in self.nodes.values_mut() {
            node.selected = false;
            node.dragging = false;
        }
        self.selection.clear();
        self.dragging_node = None;
        self.drag_start_pos = None;
    }
    
    /// Helper method to reset edges for clean path visualization
    fn reset_edges_for_path_visualization(&mut self) {
        for edge in &mut self.edges {
            edge.edge_type = EdgeType::Normal;
            edge.visible = false;
        }
    }
    
    /// Gets all current relationships from edges (internal state)
    fn get_all_current_relationships(&self) -> Vec<Relationship> {
        self.edges.iter().map(|edge| edge.relationship.clone()).collect()
    }
    
    /// Adds paths for a single component to the current path collections
    fn add_component_paths(&mut self, component_id: &str, relationships: &[Relationship]) {
        // Find and add read paths
        let component_read_paths = self.find_read_paths(component_id, relationships);
        self.read_paths.extend(component_read_paths);
        
        // Find and add write paths
        let component_write_paths = self.find_write_paths(component_id, relationships);
        self.write_paths.extend(component_write_paths);
        
        // Add hierarchical paths
        self.add_hierarchical_paths(component_id, relationships);
    }
    
    /// Applies all collected paths to the visualization
    fn apply_collected_paths(&mut self) {
        // Highlight read paths in blue
        let read_paths = self.read_paths.clone();
        for path in &read_paths {
            self.highlight_path(path, EdgeType::ReadPath);
        }
        
        // Highlight write paths in yellow
        let write_paths = self.write_paths.clone();
        for path in &write_paths {
            self.highlight_path(path, EdgeType::WritePath);
        }
        
        // Highlight all related components
        self.highlight_all_related_components();
    }
    
    /// Highlights all components that appear in any path
    fn highlight_all_related_components(&mut self) {
        let all_component_ids: std::collections::HashSet<String> = self.read_paths
            .iter()
            .chain(self.write_paths.iter())
            .flat_map(|path| path.iter())
            .cloned()
            .collect();
            
        for comp_id in all_component_ids {
            if let Some(node) = self.nodes.get_mut(&comp_id) {
                node.selected = true;
            }
            self.highlighted_components.insert(comp_id);
        }
    }
    
    /// Moves all highlighted/connected components together as a group
    fn move_connected_group(&mut self, drag_delta: Vec2) {
        let movement = drag_delta / self.zoom;
        
        // Move all highlighted components
        for comp_id in &self.highlighted_components {
            if let Some(node) = self.nodes.get_mut(comp_id) {
                node.position += movement;
            }
        }
    }

    fn find_read_paths(&self, component_id: &str, relationships: &[Relationship]) -> Vec<Vec<String>> {
        let mut read_paths = Vec::new();
        
        // Find bidirectional relationships where the component is involved
        for rel in relationships {
            let (from_id, to_id, should_highlight) = self.determine_relationship_direction(component_id, rel);
            
            if should_highlight && self.is_read_relationship(&rel.relationship_type) {
                let path = vec![from_id, to_id];
                read_paths.push(path);
                
                // Look for extended paths
                let extended_paths = self.find_extended_paths(component_id, relationships, true, 2);
                read_paths.extend(extended_paths);
            }
        }
        
        read_paths
    }

    fn find_write_paths(&self, component_id: &str, relationships: &[Relationship]) -> Vec<Vec<String>> {
        let mut write_paths = Vec::new();
        
        // Find bidirectional relationships where the component is involved
        for rel in relationships {
            let (from_id, to_id, should_highlight) = self.determine_relationship_direction(component_id, rel);
            
            if should_highlight && self.is_write_relationship(&rel.relationship_type) {
                let path = vec![from_id, to_id];
                write_paths.push(path);
                
                // Look for extended paths
                let extended_paths = self.find_extended_paths(component_id, relationships, false, 2);
                write_paths.extend(extended_paths);
            }
        }
        
        write_paths
    }

    fn find_extended_read_paths(
        &self,
        current_id: &str,
        target_id: &str,
        relationships: &[Relationship],
        max_depth: usize,
    ) -> Vec<Vec<String>> {
        if max_depth == 0 {
            return Vec::new();
        }
        
        let mut extended_paths = Vec::new();
        
        // Find what the current component reads from
        let upstream_relationships: Vec<&Relationship> = relationships.iter()
            .filter(|rel| {
                rel.target_id == current_id && 
                rel.source_id != target_id && // Avoid cycles back to original component
                (rel.relationship_type == crate::types::RelationshipType::Reads ||
                 rel.relationship_type == crate::types::RelationshipType::Uses ||
                 rel.relationship_type == crate::types::RelationshipType::Imports)
            })
            .collect();
        
        for rel in upstream_relationships {
            let path = vec![rel.source_id.clone(), current_id.to_string(), target_id.to_string()];
            extended_paths.push(path);
            
            // Recurse for deeper paths
            let deeper_paths = self.find_extended_read_paths(&rel.source_id, target_id, relationships, max_depth - 1);
            for mut deeper_path in deeper_paths {
                deeper_path.push(current_id.to_string());
                deeper_path.push(target_id.to_string());
                extended_paths.push(deeper_path);
            }
        }
        
        extended_paths
    }

    /// Determines the proper direction for a relationship arrow based on component hierarchy
    /// Returns (from_id, to_id, should_highlight) where arrows point from larger to smaller components
    fn determine_relationship_direction(&self, selected_component_id: &str, rel: &Relationship) -> (String, String, bool) {
        // Check if this relationship involves the selected component
        let involves_selected = rel.source_id == selected_component_id || rel.target_id == selected_component_id;
        
        if !involves_selected {
            return (rel.source_id.clone(), rel.target_id.clone(), false);
        }
        
        // Get component types to determine hierarchy
        let source_type = self.nodes.get(&rel.source_id)
            .map(|n| &n.component.component_type);
        let target_type = self.nodes.get(&rel.target_id)
            .map(|n| &n.component.component_type);
        
        match (source_type, target_type) {
            (Some(src_type), Some(tgt_type)) => {
                // Arrows point from larger to smaller components
                // Network > Host > Process > Binary > Function > Instruction
                if src_type > tgt_type {
                    // Source is larger, arrow goes source -> target
                    (rel.source_id.clone(), rel.target_id.clone(), true)
                } else if tgt_type > src_type {
                    // Target is larger, reverse arrow direction: target -> source
                    (rel.target_id.clone(), rel.source_id.clone(), true)
                } else {
                    // Same level, keep original direction
                    (rel.source_id.clone(), rel.target_id.clone(), true)
                }
            }
            _ => {
                // If we can't determine types, keep original direction
                (rel.source_id.clone(), rel.target_id.clone(), true)
            }
        }
    }
    
    /// Classifies relationship types as read operations
    fn is_read_relationship(&self, rel_type: &crate::types::RelationshipType) -> bool {
        matches!(rel_type, 
            crate::types::RelationshipType::Reads |
            crate::types::RelationshipType::Uses |
            crate::types::RelationshipType::Imports |
            crate::types::RelationshipType::DependsOn
        )
    }
    
    /// Classifies relationship types as write operations
    fn is_write_relationship(&self, rel_type: &crate::types::RelationshipType) -> bool {
        matches!(rel_type,
            crate::types::RelationshipType::Writes |
            crate::types::RelationshipType::Calls |
            crate::types::RelationshipType::Contains |
            crate::types::RelationshipType::Executes |
            crate::types::RelationshipType::ConnectsTo
        )
    }
    
    /// Finds extended paths in the relationship graph
    fn find_extended_paths(
        &self,
        component_id: &str,
        relationships: &[Relationship],
        is_read_path: bool,
        max_depth: usize,
    ) -> Vec<Vec<String>> {
        if max_depth == 0 {
            return Vec::new();
        }
        
        let mut extended_paths = Vec::new();
        
        // Find relationships that extend from the current component
        for rel in relationships {
            let (from_id, to_id, should_highlight) = self.determine_relationship_direction(component_id, rel);
            
            if !should_highlight {
                continue;
            }
            
            let is_relevant = if is_read_path {
                self.is_read_relationship(&rel.relationship_type)
            } else {
                self.is_write_relationship(&rel.relationship_type)
            };
            
            if is_relevant {
                // Only create extended paths if this creates a chain
                let creates_chain = (rel.source_id == component_id && from_id != component_id) ||
                                  (rel.target_id == component_id && to_id != component_id);
                
                if creates_chain {
                    let path = vec![from_id.clone(), to_id.clone()];
                    extended_paths.push(path);
                    
                    // Recursively find deeper connections
                    let other_component = if from_id == component_id { &to_id } else { &from_id };
                    let deeper_paths = self.find_extended_paths(other_component, relationships, is_read_path, max_depth - 1);
                    
                    for deeper_path in deeper_paths {
                        let mut full_path = vec![from_id.clone(), to_id.clone()];
                        full_path.extend(deeper_path.into_iter().skip(1));
                        extended_paths.push(full_path);
                    }
                }
            }
        }
        
        extended_paths
    }
    
    /// Adds parent-child relationships to ensure bidirectional highlighting
    /// When a function is selected, its binary should light up, etc.
    fn add_hierarchical_paths(&mut self, component_id: &str, relationships: &[Relationship]) {
        let selected_component_type = self.nodes.get(component_id)
            .map(|n| &n.component.component_type);
            
        if let Some(selected_type) = selected_component_type {
            // Find all relationships that involve the selected component
            for rel in relationships {
                if rel.source_id == component_id || rel.target_id == component_id {
                    let other_id = if rel.source_id == component_id {
                        &rel.target_id
                    } else {
                        &rel.source_id
                    };
                    
                    if let Some(other_node) = self.nodes.get(other_id) {
                        let other_type = &other_node.component.component_type;
                        
                        // Determine if this is a hierarchical relationship
                        let is_hierarchical = matches!(rel.relationship_type,
                            crate::types::RelationshipType::Contains |
                            crate::types::RelationshipType::DependsOn |
                            crate::types::RelationshipType::Uses
                        );
                        
                        if is_hierarchical {
                            // Add bidirectional path with proper arrow direction
                            let (from_id, to_id, _) = self.determine_relationship_direction(component_id, rel);
                            let path = vec![from_id, to_id];
                            
                            // Classify as read or write based on relationship type and hierarchy
                            if selected_type < other_type {
                                // Selected component is smaller, this is a \"read\" relationship (dependency)
                                self.read_paths.push(path);
                            } else {
                                // Selected component is larger, this is a \"write\" relationship (containment)
                                self.write_paths.push(path);
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Highlights the selected component and all related components in the visualization
    fn highlight_related_components(&mut self, component_id: &str) {
        // Highlight the main selected component
        if let Some(node) = self.nodes.get_mut(component_id) {
            node.selected = true;
        }
        
        // Highlight all components that appear in the paths
        let all_component_ids: std::collections::HashSet<String> = self.read_paths
            .iter()
            .chain(self.write_paths.iter())
            .flat_map(|path| path.iter())
            .cloned()
            .collect();
            
        for comp_id in all_component_ids {
            if let Some(node) = self.nodes.get_mut(&comp_id) {
                node.selected = true;
                self.selection.insert(comp_id);
            }
        }
    }

    fn highlight_path(&mut self, path: &[String], edge_type: EdgeType) {
        if path.len() < 2 {
            return;
        }
        
        for i in 0..path.len() - 1 {
            let from_id = &path[i];
            let to_id = &path[i + 1];
            
            // Find the edge that represents this relationship
            // We need to check both directions since our path may have reordered the relationship
            for edge in &mut self.edges {
                let edge_matches = (edge.relationship.source_id == *from_id && edge.relationship.target_id == *to_id) ||
                                 (edge.relationship.source_id == *to_id && edge.relationship.target_id == *from_id);
                
                if edge_matches {
                    edge.edge_type = edge_type.clone();
                    edge.visible = true;
                    
                    // Update edge visual direction based on path direction
                    // This ensures arrows point in the direction specified by our hierarchy-aware path
                    edge.from_pos = self.nodes.get(from_id)
                        .map(|n| n.position + n.size * 0.5)
                        .unwrap_or(edge.from_pos);
                    edge.to_pos = self.nodes.get(to_id)
                        .map(|n| n.position + n.size * 0.5)
                        .unwrap_or(edge.to_pos);
                    
                    break;
                }
            }
        }
    }
}

#[cfg(feature = "gui")]
impl Default for ComponentGraph {
    fn default() -> Self {
        Self::new()
    }
}