const configTargetsComponent = {
  schema: {
    targets: {type: 'array', default: ['']},
  },
  ensureImageTargetsConfigured() {
    if (this.configured || !this.configOk) {
      return
    }
    console.log(`Scanning for targets: ${JSON.stringify(this.data.targets)}`)
    // imageTargets 는 deprecated → imageTargets 는 그대로 두되
    // imageTargetData 방식(index.html onxrloaded)과 함께 쓸 때는
    // 여기서 이름 목록만 넘겨주면 됨
    XR8.XrController.configure({imageTargets: this.data.targets})
    this.configured = true
  },
  init() {
    this.configured = false
    this.configOk = false
    this.el.sceneEl.addEventListener('realityready', () => {
      this.configOk = true
      this.ensureImageTargetsConfigured()
    })
  },
  update() {
    this.configured = false
    this.ensureImageTargetsConfigured()
  },
}

const smartTargetComponent = {
  schema: {
    name: {type: 'string'},
  },
  init() {
    const scene = this.el.sceneEl
    const {object3D} = this.el
    const {name} = this.data
    object3D.visible = false

    const showImage = ({detail}) => {
      if (name !== detail.name) {
        return
      }
      object3D.position.copy(detail.position)
      object3D.quaternion.copy(detail.rotation)
      object3D.scale.set(detail.scale, detail.scale, detail.scale)
      object3D.visible = true
    }

    const hideImage = ({detail}) => {
      if (name !== detail.name) {
        return
      }
      object3D.visible = false
    }

    scene.addEventListener('xrimagefound', showImage)
    scene.addEventListener('xrimageupdated', showImage)
    scene.addEventListener('xrimagelost', hideImage)
  },
}

export {configTargetsComponent, smartTargetComponent}
