var width = window.outerWidth - 22,
    height = window.outerHeight * 0.9;
    //color = d3.scale.category20();


color = ["#aec7e8", "#1f77b4", "#ff7f0e", ]

// mouse event vars
var selected_node = null,
    selected_link = null,
    mousedown_node = null;

// init svg
var outer = d3.select("#chart")
  .append("svg:svg")
    .attr("width", width)
    .attr("height", height)
    .attr("pointer-events", "all");

var vis = outer
  .append('svg:g')
    .call(d3.behavior.zoom().on("zoom", rescale))
    .on("dblclick.zoom", null)
  .append('svg:g')
    .on("mousemove", mousemove)
    .on("mousedown", mousedown)
    .on("mouseup", mouseup);

vis.append('svg:rect')
    .attr('width', width)
    .attr('height', height)
    .attr('fill', 'white');

// init force layout
var force = d3.layout.force()
    .size([width, height])
    .linkDistance(100)
    .charge(-800)
    // .linkStrength(1)
    .on("tick", tick);

// get layout properties
var nodes = force.nodes(),
    links = force.links(),
    node = vis.selectAll(".node"),
    link = vis.selectAll(".link");

// add keyboard callback
// d3.select(window)
//     .on("keydown", keydown);

var load = window.location.search.replace( "?", "" );
if (load == "") {
  //load = "data/example.json";
} else {
  load = "data/" + load + ".json";
}

d3.json(load, function(graph) {
  var numSources = 0;
  var numSinks = 0;
  var numFirst = 0;
  var maxNode = 0;
  var sourceI = 0.5;
  var sinkI = 0.5;
  var firstI = 0;
  graph.nodes.forEach(function(node){
    if (node.group == 1)
      numSources++;
    if (node.group == 2)
      numSinks++;
    if (node.max == 1)
      numFirst++;
    if (node.max > maxNode)
      maxNode = node.max;
    nodes.push(node);
  });
  graph.nodes.forEach(function(node, index){
    if (node.group == 1) {
      nodes[index].x = 10;
      nodes[index].y = sourceI * height/numSources;
      nodes[index].fixed = true;
      sourceI++;
    }
    if (node.group == 2) {
      nodes[index].x = width - 120;
      nodes[index].y = sinkI * height/numSinks;
      nodes[index].fixed = true;
      sinkI++;  
    }
    if (node.max == 1) {
      nodes[index].x = Math.max(width/maxNode, 100);
      nodes[index].y = 100 + firstI * (height-200)/numFirst;
      nodes[index].fixed = true;
      firstI += 1
    }
  });
  graph.links.forEach(function(link){
    links.push(link);
  });
  redraw();
});

var tooltip = d3.select("body")
    .append("div")
    .style("position", "absolute")
    .style("z-index", "10")
    .style("visibility", "hidden")
    .attr("class", "tooltip");

 // Per-type markers, as they don't inherit styles.
vis.append("svg:defs").selectAll("marker")
    .data(["suit", "call", "instance", "static", "resolved", "file", 'intent', 'broadcast', 'contentprovider', 'return', 'callback'])
  .enter().append("svg:marker")
    .attr("id", String)
    .attr("viewBox", "0 -2 4 4")
    .attr("refX", 6)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
  .append("svg:path")
    .attr("d", "M0,-2 L4.3,0 L0,2");

// focus on svg
// vis.node().focus();

function mousedown() {
  if (!mousedown_node) {
    // allow panning if nothing is selected
    vis.call(d3.behavior.zoom().on("zoom"), rescale);
    return;
  }
}

function mousemove() {
  if (!mousedown_node) return;
}

function mouseup() {
  mousedown_node = null;
}

function tick() {
  link.attr("d", function(d) {
    var dx = d.target.x - d.source.x,
        dy = d.target.y - d.source.y,
        dr = Math.sqrt(dx * dx + dy * dy);
    return "M" + d.source.x + "," + d.source.y + "L" + d.target.x + "," + d.target.y;
  });

  node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"});

}

// rescale g
function rescale() {
  trans=d3.event.translate;
  scale=d3.event.scale;

  vis.attr("transform",
      "translate(" + trans + ")"
      + " scale(" + scale + ")");
}

// redraw force layout
function redraw() {

  link = link.data(links);

  link.enter().append("svg:path")
    .attr("class", function(d) { return "link " + d.type; })
    .attr("marker-end", function(d) { return "url(#" + d.type + ")"; });
        // .insert("line", ".node")
        // .attr("class", "link");

  link.exit().remove();

  node = node.data(nodes);

  node.enter()
    .append("g")
    .attr("class", "node")
    .call(force.drag)

  node.append("circle")
      .attr("class", "node")
      .style("fill", function(d) { return color[d.group]; })
      .attr("r", 5)
      .on("mousedown", 
        function(d) { 
          // disable zoom
          vis.call(d3.behavior.zoom().on("zoom"), null);

          mousedown_node = d;
          d.fixed = true;
          if (mousedown_node == selected_node) selected_node = null;
          else selected_node = mousedown_node;
        })
      .on("mouseover", function(d){
          tooltip.style("visibility", "visible");
          tooltip.html(d.tooltip);
        })
      .on("mousemove", function(){
          tooltip.style("top", (d3.event.pageY+10)+"px").style("left",(d3.event.pageX+10)+"px");
        })
      .on("mouseout", function(){
          tooltip.style("visibility", "hidden");
        })

    .transition()
      .duration(750)
      .ease("elastic")
      .attr("r", 6.5);

  node.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .attr("class", "shadow")
      .text(function(d) {return d.name });
  
  node.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .text(function(d) {return d.name });

  // node.exit().transition()
  //     .attr("r", 0)
  //   .remove();

  // node
  //   .classed("node_selected", function(d) { return d === selected_node; });

  if (d3.event) {
    // prevent browser's default behavior
    d3.event.preventDefault();
  }

  force.start();
}

// function keydown() {
//   if (!selected_node && !selected_link) return;
//   switch (d3.event.keyCode) {
//     case 8: // backspace
//     case 46: { // delete
//     }
//   }
// }

d3.json('data/available_files.json', function(graph) {
   var sel = d3.select('#select_file');
  graph.files.forEach(function(row){
    sel.append("option")
      .attr("value", row.name)
      .text(row.name);
    });
  //
   var dd = document.getElementById('select_file');
  var sel = window.location.search.replace( "?", "" );
  if (sel === '') {
    dd.options[0].defaultSelected = true;
  } else {
    for (var i = 0; i < dd.options.length; i++) {
        if (dd.options[i].text === sel) {
            dd.options[i].defaultSelected = true;
            break;
        }
    }
  }
});